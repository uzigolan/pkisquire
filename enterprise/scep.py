# scep.py
import base64
import os
import datetime
import plistlib
import re
from base64 import b64decode


import tempfile
import secrets
import sqlite3
import subprocess



from flask import (
    Blueprint, g, current_app, request, Response, url_for, abort
)
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from asn1crypto.csr import CertificationRequestInfo

from message import SCEPMessage
from ca import CertificateAuthority
from enums import MessageType, PKIStatus, FailInfo
from builders import PKIMessageBuilder, Signer, create_degenerate_pkcs7
from envelope import PKCSPKIEnvelopeBuilder
from config_storage import ConfigStorage
from openssl_utils import get_provider_args
from ra_policies import RAPolicyManager, DEFAULT_VALIDITY_DAYS


scep_app = Blueprint('scep_app', __name__)


# what we expose via GetCACaps
CACAPS = (
    'POSTPKIOperation',
    'SHA-1',
    'SHA-256',
    'AES',
    'DES3',
    'SHA-512',
    'Renewal',
)


def _get_ra_mgr():
    return RAPolicyManager(current_app.config["DB_PATH"], current_app.logger)


@scep_app.before_app_request
def log_scep_request():
    # Only log requests destined for our blueprint
    if request.path.startswith(f"{scep_app.url_prefix}"):
        current_app.logger.debug(
            "→ SCEP incoming request: %s %s?%s from %s",
            request.method,
            request.path,
            request.query_string.decode('utf-8'),
            request.remote_addr
        )


#@scep_app.route('/', methods=['GET', 'POST'])
@scep_app.route('/cgi-bin/pkiclient.exe', methods=['GET', 'POST'])
@scep_app.route('/scep', methods=['GET', 'POST'])
def scep():
  # Use DB for challenge password validation/consumption
  if not current_app.config.get('SCEP_ENABLED', True):
      current_app.logger.debug("SCEP disabled by configuration")
      return abort(404)
  current_app.logger.debug("Entering SCEP endpoint")
  op = request.args.get('operation')
  current_app.logger.info("SCEP operation=%s, method=%s", op, request.method)

  # optional dump dir
  dump_dir = current_app.config.get('SCEPY_DUMP_DIR')
  if dump_dir:
    os.makedirs(dump_dir, exist_ok=True)
  dump_prefix = f"request-{datetime.datetime.utcnow().timestamp()}"

  # SCEP always uses legacy mode (file-based keys)
  # SCEP protocol requires direct private key access for PKCS#7 envelope operations
  # which is not compatible with Vault's key isolation model
  current_app.logger.debug("SCEP: Using file-based CA (SCEP requires local private key)")
  
  storage = ConfigStorage(
    key_path   = current_app.config['SUBCA_KEY_PATH'],
    cert_path  = current_app.config['SUBCA_CERT_PATH'],
    chain_path = current_app.config['CHAIN_FILE_PATH'],
    serial_path= current_app.config.get('SCEP_SERIAL_PATH'),
    password   = None
  )

  if not storage.exists():
    current_app.logger.error(
      "ConfigStorage: CA files missing at %s / %s",
      storage._key_path, storage._cert_path
    )
    abort(500, "CA not initialized")

  g.ca = CertificateAuthority(
    key_path=storage._key_path,
    chain_path=storage._chain_path
  )

  ca   = g.ca

  # --- GetCACaps ---
  if op == 'GetCACaps':
    current_app.logger.debug("Handling GetCACaps")
    return Response("\n".join(CACAPS) + "\n", mimetype='text/plain')

  # --- GetCACert ---
  if op == 'GetCACert':
    current_app.logger.debug("Handling GetCACert")
    der = ca.certificate.public_bytes(Encoding.DER)
    return Response(der, mimetype='application/x-x509-ca-cert')

  # --- PKIOperation ---
  if op == 'PKIOperation' and request.method in ('GET','POST'):
    # 1) grab raw PKCS#7 payload
    if request.method == 'GET':
      raw = b64decode(request.args.get('message','').replace(' ', '+'))
    else:
      raw = (request.environ.get('body_copy')
             if 'chunked' in request.headers.get('Transfer-Encoding','')
             else request.get_data())
    current_app.logger.debug("Raw PKIOperation payload: %d bytes", len(raw))

    # optional dump of the raw P7
    if dump_dir:
      fn = os.path.join(dump_dir, dump_prefix + '.bin')
      open(fn,'wb').write(raw)
      current_app.logger.debug("Dumped raw request to %s", fn)


    # 2) parse & decrypt to get the DER CSR
    req     = SCEPMessage.parse(raw)
    der_csr = req.get_decrypted_envelope_data(ca.certificate, ca.private_key)
    current_app.logger.debug("Decrypted CSR length: %d bytes", len(der_csr))
    current_app.logger.debug("Request message type: %s", req.message_type)

    if dump_dir:
      fn = os.path.join(dump_dir, dump_prefix + '.csr')
      open(fn,'wb').write(der_csr)
      current_app.logger.debug("Dumped CSR to %s", fn)

    # Challenge password validation using OpenSSL
    challenge_enabled = current_app.config.get('SCEP_CHALLENGE_PASSWORD_ENABLED', False)
    challenge_user_id = None
    if challenge_enabled and req.message_type in (MessageType.PKCSReq, MessageType.RenewalReq):
      with tempfile.NamedTemporaryFile(delete=False, suffix=".csr") as tmp_csr:
        tmp_csr.write(der_csr)
        temp_csr_path = tmp_csr.name
      try:
        openssl_cmd = [
          "openssl", "req", "-in", temp_csr_path, "-inform", "DER", "-noout", "-text"
        ]
        result = subprocess.run(openssl_cmd, capture_output=True, text=True)
        challenge_value = None
        if result.returncode == 0:
          for line in result.stdout.splitlines():
            if "challengePassword" in line:
              challenge_value = line.split(":", 1)[-1].strip()
              current_app.logger.info(f"Extracted challengePassword via OpenSSL: {challenge_value}")
              break
        if not challenge_value:
          current_app.logger.error("Failed to extract challengePassword from CSR using OpenSSL.")
          return abort(400, "Missing or invalid challengePassword in CSR")

        # Validate challenge password against DB
        db_path = current_app.config.get("DB_PATH")
        with sqlite3.connect(db_path) as conn:
          cur = conn.cursor()
          cur.execute("SELECT consumed, user_id, validity, created_at FROM challenge_passwords WHERE value = ?", (challenge_value,))
          row = cur.fetchone()
          if not row:
            current_app.logger.error(f"Challenge password {challenge_value} not found in DB.")
            return abort(400, "Challenge password not recognized or expired")
          consumed, user_id, validity, created_at = row
          if consumed:
            current_app.logger.error(f"Challenge password {challenge_value} already consumed.")
            return abort(400, "Challenge password already used")
          # Check expiry
          m = re.match(r'^(\d+)([mhd])$', validity)
          if m:
            num, unit = int(m.group(1)), m.group(2)
            if unit == 'm':
              delta = datetime.timedelta(minutes=num)
            elif unit == 'h':
              delta = datetime.timedelta(hours=num)
            elif unit == 'd':
              delta = datetime.timedelta(days=num)
            else:
              delta = datetime.timedelta(minutes=60)
          else:
            delta = datetime.timedelta(minutes=60)
          try:
            created_dt = datetime.datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S UTC')
          except Exception:
            # Treat unparsable timestamps as already expired
            created_dt = datetime.datetime.utcnow() - datetime.timedelta(days=1)
          expires_at = created_dt + delta
          if datetime.datetime.utcnow() > expires_at:
            current_app.logger.error(f"Challenge password {challenge_value} expired at {expires_at}.")
            return abort(400, "Challenge password expired")
          # Optionally log user_id and validity
          current_app.logger.info(f"Challenge password {challenge_value} accepted for user_id={user_id}, validity={validity}")
          challenge_user_id = user_id
          # Mark as consumed
          cur.execute("UPDATE challenge_passwords SET consumed = 1 WHERE value = ?", (challenge_value,))
          conn.commit()
      finally:
        if os.path.exists(temp_csr_path):
          os.unlink(temp_csr_path)

    # only handle PKCSReq or RenewalReq
    if req.message_type in (MessageType.PKCSReq, MessageType.RenewalReq):
      # write CSR to temp file
      csr_tmp  = tempfile.NamedTemporaryFile(delete=False, suffix=".csr")
      csr_tmp.write(der_csr)
      csr_tmp.close()

      # prepare output cert temp file
      cert_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
      cert_tmp.close()

      # pick ext-block, serial, validity
      ext_block        = request.form.get("ext_block", "v3_ext")
      custom_serial    = hex(secrets.randbits(64))
      mgr = _get_ra_mgr()
      policy = mgr.get_protocol_default("scep")
      validity_days = mgr.get_validity_days(policy)
      try:
        validity_int = int(str(validity_days))
      except Exception:
        validity_int = int(DEFAULT_VALIDITY_DAYS)

      # 3) invoke openssl x509 -req
      SUBCA_CERT_PATH   = current_app.config['SUBCA_CERT_PATH']
      SUBCA_KEY_PATH    = current_app.config['SUBCA_KEY_PATH']

      try:
        with mgr.temp_extfile(policy) as extfile_path:
          if not extfile_path:
            return abort(500, "No RA policy extension config available")
          cmd = ["openssl","x509"]
          cmd.extend(get_provider_args())
          cmd.extend(["-req",
            "-in",   csr_tmp.name,
            "-CA",   SUBCA_CERT_PATH,
            "-CAkey",SUBCA_KEY_PATH,
#        "-set_serial", custom_serial,
            "-CAcreateserial",
            "-days", str(validity_int),  # subprocess expects strings
            "-extfile", extfile_path,
            "-extensions", ext_block,
            "-out",  cert_tmp.name
          ])
          current_app.logger.debug("Running OpenSSL: %s", " ".join(str(x) for x in cmd))
          subprocess.run(cmd, check=True, capture_output=True, text=True)
      except subprocess.CalledProcessError as e:
        current_app.logger.error("OpenSSL signing failed: %s", e.stderr)
        os.unlink(csr_tmp.name)
        os.unlink(cert_tmp.name)
        return abort(500, "Signing failed")

      # 4) load the resulting PEM cert
      cert_pem = open(cert_tmp.name,"r").read()
      cert_obj = x509.load_pem_x509_certificate(
        cert_pem.encode(), default_backend()
      )
      actual_serial = hex(cert_obj.serial_number)

      # Debug: log the certificate subject to verify it's correct
      current_app.logger.debug("Issued certificate subject: %s", cert_obj.subject.rfc4514_string())


      # build the same subject_str you use elsewhere
      try:
        subject_str = ", ".join(
          f"{attr.oid._name}={attr.value}"
          for attr in cert_obj.subject
        )
      except Exception:
        subject_str = "Unknown Subject"


      # 5) store in your sqlite DB
      DB_PATH           = current_app.config['DB_PATH']
      with sqlite3.connect(DB_PATH) as conn:
        # Store user_id if available
        if challenge_user_id is not None:
            conn.execute(
                "INSERT INTO certificates (subject, serial, cert_pem, issued_via, user_id) VALUES (?,?,?,?,?)",
                (
                    subject_str,
                    actual_serial,
                    cert_pem,
                    'scep',
                    challenge_user_id
                )
            )
        else:
            conn.execute(
                "INSERT INTO certificates (subject, serial, cert_pem, issued_via) VALUES (?,?,?,?)",
                (
                    subject_str,
                    actual_serial,
                    cert_pem,
                    'scep'
                )
            )
        conn.commit()

      # Log event for SCEP certificate issuance
      try:
        from events import log_event
        log_event(
          event_type="create",
          resource_type="certificate",
          resource_name=actual_serial,
          user_id=challenge_user_id if challenge_user_id is not None else "scep",
          details={
            "subject": subject_str,
            "issued_via": "scep"
          }
        )
      except Exception as e:
        current_app.logger.error(f"Failed to log SCEP certificate event: {e}")

      # cleanup CSR + cert files
      os.unlink(csr_tmp.name)
      os.unlink(cert_tmp.name)

      # 6) wrap & encrypt as SCEP response
      # Only include the issued certificate, not the CA certificate
      # (sscep already has the CA cert and including it causes confusion)
      deg = create_degenerate_pkcs7(cert_obj)
      envelope, _, _ = (
        PKCSPKIEnvelopeBuilder()
          .encrypt(deg.dump(), 'aes256')
          .add_recipient(req.certificates[0])
          .finalize()
      )
      signer = Signer(ca.certificate, ca.private_key, 'sha256')
      reply  = (
        PKIMessageBuilder()
          .message_type(MessageType.CertRep)
          .transaction_id(req.transaction_id)
          .pki_status(PKIStatus.SUCCESS)
          .recipient_nonce(req.sender_nonce)
          .sender_nonce()
          .pki_envelope(envelope)
          .add_signer(signer)
          .finalize()
      )

      out = reply.dump()
      current_app.logger.debug("Returning SCEP CertRep (%d bytes)", len(out))
      return Response(out, mimetype='application/x-pki-message')

    # any other SCEP message type is unsupported
    current_app.logger.error("Unsupported SCEP message type: %s", req.message_type)
    return Response("Bad Request", status=400)

  # operation not recognized
  current_app.logger.error("Unsupported SCEP operation: %s", op)
  return abort(404, "Unknown SCEP operation")





@scep_app.route('/mobileconfig')
def mobileconfig():
    """Quick Apple .mobileconfig for testing."""
    scep_url = url_for('scep_app.scep', _external=True)
    current_app.logger.debug("Generating mobileconfig with URL %s", scep_url)

    payload = {
        'PayloadType':        'Configuration',
        'PayloadDisplayName': 'SCEPy Enrollment Profile',
        'PayloadDescription': 'Enrol via SCEP',
        'PayloadVersion':     1,
        'PayloadIdentifier':  'com.example.scepy',
        'PayloadUUID':        '16D129CA-DA22-4749-82D5-A28201622555',
        'PayloadContent': [{
            'PayloadType':        'com.apple.security.scep',
            'PayloadVersion':     1,
            'PayloadIdentifier':  'com.example.scepy.scep',
            'PayloadUUID':        '7F165A7B-FACE-4A6E-8B56-CA3CC2E9D0BF',
            'PayloadDisplayName': 'SCEP Enrollment',
            'PayloadContent': {
                'URL':       scep_url,
                'Name':      'SCEPy',
                'Keysize':   2048,
                'Key Usage': 5,
                **({'Challenge': current_app.config['SCEPY_CHALLENGE']}
                   if 'SCEPY_CHALLENGE' in current_app.config else {})
            }
        }]
    }

    data = plistlib.dumps(payload)
    return Response(data, content_type='application/x-apple-aspen-config')
