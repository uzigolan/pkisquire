import os
import sqlite3
import logging
import subprocess
import tempfile
import io
import zipfile
import configparser
import secrets
import configparser
import tempfile
import base64

import binascii
import re
import ssl

from pathlib import Path
from datetime import datetime,timezone, timedelta

from threading import Thread

from flask import Flask, render_template, request, redirect, send_file, make_response, flash, url_for, Response, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import CertificateBuilder, load_pem_x509_certificate, random_serial_number
from cryptography.x509.ocsp import OCSPResponseBuilder, OCSPCertStatus, load_der_ocsp_request,OCSPResponderEncoding,OCSPResponseStatus
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization 
from markupsafe import escape
from asn1crypto import x509 as asn1_x509

from ldap_utils import ldap_authenticate, ldap_user_exists
from user_models import User, get_user_by_id
# Load shared extensions and blueprints
from extensions import db           # Shared SQLAlchemy instance
from x509_profiles import x509_profiles_bp, Profile, X509_PROFILE_DIR
from x509_keys import x509_keys_bp, Key
from x509_requests import x509_requests_bp
from scep import scep_app
from openssl_utils import get_provider_args

#from flask import render_template, current_app as app
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# --- User Registration, Login, Logout Routes ---
from user_models import get_user_by_username, create_user_db, update_last_login


# --- Manage Users (Admin Only) ---
from user_models import get_all_users


# --- API endpoint for AJAX login status polling ---
from flask import jsonify



# --- Server-side session tracking for all logged-in users ---
def ensure_sessions_table():
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER,
            login_time TEXT,
            last_activity TEXT
        )''')
        # Ensure last_activity column exists if table was created earlier without it
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(user_sessions)")
        cols = [row[1] for row in cur.fetchall()]
        if "last_activity" not in cols:
            conn.execute("ALTER TABLE user_sessions ADD COLUMN last_activity TEXT")
        # Backfill last_activity where missing
        conn.execute("""
            UPDATE user_sessions
            SET last_activity = login_time
            WHERE last_activity IS NULL OR last_activity = ''
        """)
        conn.commit()

import uuid
from flask import session as flask_session
from flask_login import user_logged_in, user_logged_out


from flask_login import user_logged_in, user_logged_out



app = Flask(__name__, template_folder="html_templates")


@user_logged_in.connect_via(app)
def track_user_logged_in(sender, user):
    ensure_sessions_table()
    sid = flask_session.get('sid')
    if not sid:
        sid = str(uuid.uuid4())
        flask_session['sid'] = sid
    now_str = _now_utc_str()
    flask_session['last_activity'] = now_str
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute("INSERT OR REPLACE INTO user_sessions (session_id, user_id, login_time, last_activity) VALUES (?, ?, ?, ?)", (sid, user.id, now_str, now_str))

@user_logged_out.connect_via(app)
def track_user_logged_out(sender, user):
    sid = flask_session.get('sid')
    if sid:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            conn.execute("DELETE FROM user_sessions WHERE session_id = ?", (sid,))
        flask_session.pop('sid', None)

def get_logged_in_user_ids():
    ensure_sessions_table()
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        rows = conn.execute("SELECT DISTINCT user_id FROM user_sessions").fetchall()
        return set(row[0] for row in rows)

def get_user_idle_map():
    """
    Returns {user_id: 'HH:MM'} for users with a recorded last_activity/login_time.
    """
    ensure_sessions_table()
    now = datetime.now(timezone.utc)
    idle = {}
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        rows = conn.execute("""
            SELECT user_id, MAX(COALESCE(last_activity, login_time)) AS last_ts
            FROM user_sessions
            GROUP BY user_id
        """).fetchall()
    for user_id, last_ts in rows:
        parsed = _parse_ts_utc(last_ts)
        if not parsed:
            continue
        delta = now - parsed
        if delta.total_seconds() < 0:
            continue
        minutes = int(delta.total_seconds() // 60)
        hours = minutes // 60
        minutes = minutes % 60
        idle[user_id] = f"{hours:02d}:{minutes:02d}"
    return idle

# Track logged-in users by user_id in a set
import threading
LOGGED_IN_USERS = set()
LOGGED_IN_USERS_LOCK = threading.Lock()
LDAP_IMPORTED_USERS = set()  # runtime memory of users created via LDAP
LDAP_SOURCE_CACHE = {}  # username -> 'ldap'|'local' for this runtime

def parse_idle_time(value: str):
    if not value:
        return None
    s = str(value).strip().lower()
    try:
        if s.endswith("h"):
            num = float(s[:-1])
            return timedelta(hours=num)
        if s.endswith("d"):
            num = float(s[:-1])
            return timedelta(days=num)
        # fallback: treat as days if numeric only
        num = float(s)
        return timedelta(days=num)
    except Exception:
        return None

def _now_utc_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def _parse_ts_utc(ts: str):
    if not ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            dt = datetime.strptime(ts, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def cleanup_idle_sessions():
    """Remove stale sessions that exceeded IDLE_TIMEOUT, regardless of who is logged in."""
    idle_timeout = app.config.get("IDLE_TIMEOUT")
    if not idle_timeout:
        return
    cutoff = datetime.now(timezone.utc) - idle_timeout
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    ensure_sessions_table()
    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            conn.execute(
                "DELETE FROM user_sessions WHERE COALESCE(last_activity, login_time) < ?",
                (cutoff_str,)
            )
            conn.commit()
    except Exception:
        pass

def get_auth_source_for_username(username: str) -> str:
    """Best-effort determination of user source without touching DB schema."""
    key = (username or "").lower()
    if not key:
        return "local"
    if key in LDAP_SOURCE_CACHE:
        return LDAP_SOURCE_CACHE[key]
    # Prefer DB value if user exists
    try:
        from user_models import get_user_by_username
        user = get_user_by_username(username)
        if user:
            LDAP_SOURCE_CACHE[key] = getattr(user, "auth_source", "local")
            return LDAP_SOURCE_CACHE[key]
    except Exception:
        pass
    if app.config.get("LDAP_ENABLED") and ldap_user_exists(username, app.config, app.logger):
        LDAP_SOURCE_CACHE[key] = "ldap"
        return "ldap"
    LDAP_SOURCE_CACHE[key] = "local"
    return "local"



# Define base paths and certificate configuration
basedir = os.path.abspath(os.path.dirname(__file__))

# —— load config.ini ——
CONFIG_PATH = os.path.join(basedir, "config.ini")
_cfg = configparser.ConfigParser()
_cfg.read(CONFIG_PATH)

# — General Flask —
app.config["SECRET_KEY"] = _cfg.get("DEFAULT", "SECRET_KEY", fallback="please-set-me")
app.config["DELETE_SECRET"] = _cfg.get("DEFAULT", "SECRET_KEY", fallback="please-set-me")
HTTP_DEFAULT_PORT          = _cfg.getint("DEFAULT", "http_port", fallback=80)
app.config["MAX_IDLE_TIME"] = _cfg.get("DEFAULT", "max_idle_time", fallback="7d")
app.config["IDLE_TIMEOUT"] = parse_idle_time(app.config.get("MAX_IDLE_TIME"))


ca_mode = _cfg.get("CA", "mode", fallback="EC").upper()
if ca_mode not in ("EC", "RSA"):
    ca_mode = "EC"

app.config["SUBCA_KEY_PATH"]   = _cfg.get("CA", f"SUBCA_KEY_PATH_{ca_mode}")
app.config["SUBCA_CERT_PATH"]  = _cfg.get("CA", f"SUBCA_CERT_PATH_{ca_mode}")
app.config["CHAIN_FILE_PATH"]  = _cfg.get("CA", f"CHAIN_FILE_PATH_{ca_mode}")
app.config["ROOT_CERT_PATH"]   = _cfg.get("CA", "ROOT_CERT_PATH")
app.config["CA_MODE"]          = ca_mode
app.config["LDAP_HOST"]           = _cfg.get("LDAP", "LDAP_HOST", fallback=None)
app.config["LDAP_PORT"]           = _cfg.getint("LDAP", "LDAP_PORT", fallback=389)
app.config["LDAP_BASE_DN"]        = _cfg.get("LDAP", "BASE_DN", fallback=None)
app.config["LDAP_PEOPLE_DN"]      = _cfg.get("LDAP", "PEOPLE_DN", fallback=None)
app.config["LDAP_ADMIN_DN"]       = _cfg.get("LDAP", "ADMIN_DN", fallback=None)
app.config["LDAP_ADMIN_PASSWORD"] = _cfg.get("LDAP", "ADMIN_PASSWORD", fallback=None)
app.config["LDAP_ENABLED"]        = _cfg.getboolean("LDAP", "enabled", fallback=bool(_cfg.get("LDAP", "LDAP_HOST", fallback=None)))

# —— SCEP section —— 
app.config["SCEP_ENABLED"]   = _cfg.getboolean("SCEP", "enabled", fallback=True)
app.config["SCEP_SERIAL_PATH"] = _cfg.get("SCEP", "serial_file", fallback=None)
app.config["SCEPY_DUMP_DIR"]   = _cfg.get("SCEP", "dump_dir", fallback=None)
HTTP_SCEP_PORT                = _cfg.getint("SCEP", "http_port", fallback=9090)

# —— HTTPS section —— 
SSL_CERT_PATH = _cfg.get("HTTPS", "ssl_cert")
SSL_KEY_PATH  = _cfg.get("HTTPS", "ssl_key")
HTTPS_PORT    = _cfg.getint("HTTPS", "port", fallback=5443)

# —— Trusted HTTPS section ——
TRUSTED_SSL_CERT_PATH = _cfg.get("TRUSTED_HTTPS", "trusted_ssl_cert")
TRUSTED_SSL_KEY_PATH  = _cfg.get("TRUSTED_HTTPS", "trusted_ssl_key")
TRUSTED_HTTPS_PORT    = _cfg.getint("TRUSTED_HTTPS", "trusted_port", fallback=5443)



# —— Other paths —— 
app.config["CRL_PATH"]         = os.path.join(basedir, _cfg.get("PATHS", "crl_path"))
app.config["SERVER_EXT_PATH"]  = os.path.join(basedir, _cfg.get("PATHS", "server_ext_cfg"))
app.config["VALIDITY_CONF"]    = os.path.join(basedir, _cfg.get("PATHS", "validity_conf"))
app.config["DB_PATH"]          = os.path.join(basedir, _cfg.get("PATHS", "db_path"))



# Flask and SQLAlchemy configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + app.config["DB_PATH"]
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "marketing"  # Replace with a secure unique secret in production

db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(int(user_id))

# ---------- Logging Setup ----------
import sys
import os
import logging
from logging import Formatter
from logging.handlers import RotatingFileHandler

# Put logs in ./logs/server.log (create dir if needed)
basedir = os.path.abspath(os.path.dirname(__file__))
LOG_DIR = os.path.join(basedir, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "server.log")
app.config["LOG_FILE"] = LOG_FILE  # expose to routes

# One rotating file handler (no stdout handler to avoid confusion)
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
formatter = Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
file_handler.setFormatter(formatter)

# Apply to Flask app logger
app.logger.handlers.clear()
app.logger.setLevel(logging.DEBUG)
app.logger.addHandler(file_handler)
app.logger.propagate = False

# Also capture Werkzeug (request logs) into the same file
werkzeug_logger = logging.getLogger("werkzeug")
werkzeug_logger.handlers.clear()
werkzeug_logger.setLevel(logging.INFO)
werkzeug_logger.addHandler(file_handler)
werkzeug_logger.propagate = False

app.logger.info("Logging initialized. Writing to %s", LOG_FILE)


# ---------- Database Initialization ----------

VERSION_FILE = Path(__file__).parent / "version.txt"

try:
    APP_VERSION = VERSION_FILE.read_text().strip()
except FileNotFoundError:
    APP_VERSION = "unknown"

@app.context_processor
def inject_app_version():
    # makes `version` available in all templates
    return dict(version=APP_VERSION)



with app.app_context():
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS certificates (
                            id INTEGER PRIMARY KEY,
                            subject TEXT,
                            serial TEXT,
                            cert_pem TEXT,
                            revoked INTEGER DEFAULT 0
                        )''')
    db.create_all()

# ---------- Register Blueprints ----------
app.register_blueprint(x509_profiles_bp)
app.register_blueprint(x509_keys_bp)
app.register_blueprint(x509_requests_bp)
app.register_blueprint(scep_app)
# ---------- Helper Functions ----------





OID_TO_NAME = {
    # Dilithium2
    "1.3.6.1.4.1.2.267.7.4.4": "mldsa44",
    # Dilithium3
    "1.3.6.1.4.1.2.267.7.6.5": "mldsa65",
    # Dilithium5
    "1.3.6.1.4.1.2.267.7.8.7": "mldsa87",
    # you can add more mappings here
}

import re

def certificate_to_dict(cert):
    def oid_name(oid):
        return getattr(oid, "_name", None) or oid.dotted_string

    # 1) Try the native API first
    try:
        pub = cert.public_key()
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        if isinstance(pub, rsa.RSAPublicKey):
            algo, params = "RSA", f"{pub.key_size} bits"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            algo, params = "EC", pub.curve.name
        else:
            raise ValueError("unknown key class")
    except Exception:
        # 2) Try ASN.1 fallback
        try:
            der = cert.public_bytes(Encoding.DER)
            asn1c = asn1_x509.Certificate.load(der)
            spki = asn1c["tbs_certificate"]["subject_public_key_info"]
            oid = spki["algorithm"]["algorithm"].dotted
            algo, params = OID_TO_NAME.get(oid, oid), ""
        except Exception:
            # 3) Last resort: call openssl -text
            pem = cert.public_bytes(Encoding.PEM).decode("ascii")
            with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".pem") as tmp:
                tmp.write(pem)
                path = tmp.name

            proc = subprocess.run(
                ["openssl", "x509", "-in", path, "-noout", "-text"],
                capture_output=True, text=True
            )
            # clean up immediately
            try: subprocess.run(["rm", "-f", path])
            except: pass

            algo = params = ""
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line.startswith("Public Key Algorithm:"):
                    algo = line.split(":", 1)[1].strip()
                m = re.match(r"Public-Key:\s*\((\d+ bit)\)", line)
                if m:
                    params = m.group(1)
                elif line.startswith("ASN1 OID:"):
                    params = line.split(":", 1)[1].strip()

    # build the rest of the dict
    details = {
        "Public Key Algorithm": algo,
        "Public Key Parameters": params,
        "Subject":    { oid_name(a.oid): a.value for a in cert.subject },
        "Issuer":     { oid_name(a.oid): a.value for a in cert.issuer },
        "Serial Number":    hex(cert.serial_number),
        "Version":          str(cert.version.name),
        "Not Valid Before": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%MZ"),
        "Not Valid After":  cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%MZ"),
        "Signature Algorithm": oid_name(cert.signature_algorithm_oid),
        "Extensions":       {}
    }
    for ext in cert.extensions:
        name = oid_name(ext.oid)
        details["Extensions"][name] = str(ext.value)
    return details


def certificate_to_dictY(cert):
    def get_oid_name(oid):
        return getattr(oid, "_name", None) or oid.dotted_string

    cert_details = {
        "Subject": {get_oid_name(attr.oid): attr.value for attr in cert.subject},
        "Issuer": {get_oid_name(attr.oid): attr.value for attr in cert.issuer},
        "Serial Number": hex(cert.serial_number),
        "Version": str(cert.version.name),
        "Not Valid Before": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%SZ"),
        "Not Valid After": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%SZ"),
        "Signature Algorithm": get_oid_name(cert.signature_algorithm_oid),
        "Extensions": {}
    }
    for ext in cert.extensions:
        ext_name = get_oid_name(ext.oid)
        cert_details["Extensions"][ext_name] = str(ext.value)
    
    # Add Public Key Information: algorithm, key size (for RSA) or curve (for EC)
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        cert_details["Public Key Algorithm"] = "RSA"
        cert_details["Key Size"] = f"{public_key.key_size} bits"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        cert_details["Public Key Algorithm"] = "EC"
        cert_details["Curve"] = public_key.curve.name
    else:
        cert_details["Public Key Algorithm"] = type(public_key).__name__
    
    return cert_details


def certificate_to_dictX(cert):
    def get_oid_name(oid):
        return getattr(oid, "_name", None) or oid.dotted_string

    cert_details = {
        "Subject": {get_oid_name(attr.oid): attr.value for attr in cert.subject},
        "Issuer": {get_oid_name(attr.oid): attr.value for attr in cert.issuer},
        "Serial Number": hex(cert.serial_number),
        "Version": str(cert.version.name),
        "Not Valid Before": cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%SZ"),
        "Not Valid After": cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%SZ"),
        "Signature Algorithm": get_oid_name(cert.signature_algorithm_oid),
        "Extensions": {}
    }
    for ext in cert.extensions:
        ext_name = get_oid_name(ext.oid)
        cert_details["Extensions"][ext_name] = str(ext.value)
    return cert_details


def get_certificate_text(pem: str) -> str:
    # Use OpenSSL to parse certificate text with optional oqsprovider
    with tempfile.NamedTemporaryFile("w+", suffix=".pem", delete=False) as f:
        f.write(pem)
        f.flush()
        cmd = ["openssl", "x509"]
        # Add provider args if oqsprovider is available
        cmd.extend(get_provider_args())
        cmd.extend(["-in", f.name, "-noout", "-text"])
        p = subprocess.run(cmd, capture_output=True, text=True)
        return p.stdout or p.stderr



def get_certificate_textY(cert_pem):
    try:
        proc = subprocess.Popen(
            ["openssl", "x509", "-noout", "-text"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(input=cert_pem.encode("utf-8"))
        if proc.returncode != 0:
            return f"Error: {stderr.decode('utf-8')}"
        return stdout.decode("utf-8")
    except Exception as e:
        app.logger.error(f"Failed to run openssl: {str(e)}")
        return f"Failed to run openssl: {str(e)}"

# ---------- Main Routes ----------
@app.context_processor
def inject_ca_mode():
    # so every template gets a 'ca_mode' variable
    return {"ca_mode": app.config["CA_MODE"]}


OID_TO_NAME = {
    "2.16.840.1.101.3.4.3.17":  "PQC/mldsa44",
    "1.3.6.1.4.1.2.267.7.4.4":   "PQC/mldsa65",
    "1.3.6.1.4.1.2.267.7.6.5":   "PQC/mldsa87",
}


def extract_keycol_with_openssl(pem_bytes: bytes) -> str:
    """Run `openssl x509 -text` on the cert and return Key column like “RSA/4096”,
    “EC/prime256v1” or “PQC/mldsa44”."""
    # dump to temp file
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as t:
        t.write(pem_bytes)
        t.flush()
        path = t.name

    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout", "-text"],
            capture_output=True, text=True
        )
        text = proc.stdout or proc.stderr
    finally:
        os.remove(path)

    algo = None
    bits = None
    oid_val = None

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Public Key Algorithm:"):
            algo = line.split(":", 1)[1].strip()
        m = re.search(r"\((\d+)\s+bit\)", line)
        if m:
            bits = m.group(1)
        if line.startswith("ASN1 OID:"):
            oid_val = line.split(":", 1)[1].strip()

    # 1) PQC case: if OpenSSL directly printed “mldsaXX”
    if algo and algo.lower().startswith("mldsa"):
        return f"PQC/{algo}"

    # 2) RSA
    if algo and algo.upper().startswith("RSA"):
        return f"RSA/{bits}" if bits else "RSA"

    # 3) EC (ECDSA)
    if algo and ("EC" in algo.upper() or "ECDSA" in algo.upper()):
        # prefer curve name if it showed up as an OID, else bits
        curve = oid_val if oid_val in OID_TO_NAME.keys() or algo.startswith("id-ec") else None
        if curve:
            # map e.g. id-ecPublicKey oid to actual curve name?
            # you can extend OID → name map for EC curves if needed
            return f"EC/{curve}"
        return f"EC/{bits or algo}"

    # 4) fallback by OID lookup (for any other PQC schemes you map via OID_TO_NAME)
    if oid_val:
        name = OID_TO_NAME.get(oid_val)
        if name:
            return f"PQC/{name}"
        return f"PQC/{oid_val}"

    # 5) ultimate fallback
    return algo or "Unknown"

@app.route('/toggle_user_active/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_active(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('manage_users'))
    from user_models import get_user_by_id
    user = get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('manage_users'))
    # Toggle between 'active' and 'deactivated'
    import sqlite3
    new_status = 'deactivated' if user.status == 'active' else 'active'
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    flash(f'User {"activated" if new_status == "active" else "deactivated"}.', 'success')
    return redirect(url_for('manage_users'))


@app.before_request
def enforce_session_revocation():
    from flask_login import current_user, logout_user
    cleanup_idle_sessions()
    app.logger.debug("revocation check path=%s user_id=%s", request.path, getattr(current_user, 'id', None))
    if current_user.is_authenticated:
        sid = session.get('sid')
        if not sid:
            # Defensive: if no sid, treat as invalid session
            app.logger.debug("Session revocation: missing sid for user_id=%s", getattr(current_user, 'id', None))
            logout_user()
            flash('Your session has expired or was revoked.', 'warning')
            return redirect(url_for('login'))
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            row = conn.execute("SELECT 1 FROM user_sessions WHERE session_id = ?", (sid,)).fetchone()
            if not row:
                app.logger.debug("Session revocation: sid %s not found in user_sessions (user_id=%s)", sid, getattr(current_user, 'id', None))
                logout_user()
                session.pop('sid', None)
                flash('You have been logged out by an administrator.', 'warning')
                return redirect(url_for('login'))

@app.before_request
def enforce_idle_timeout():
    from flask_login import current_user, logout_user
    idle_timeout = app.config.get("IDLE_TIMEOUT")
    if not idle_timeout:
        return

    # Update last activity for authenticated users; logout if over threshold
    now = datetime.now(timezone.utc)
    if not current_user.is_authenticated:
        session.pop('last_activity', None)
        return

    ensure_sessions_table()
    sid = session.get('sid')
    app.logger.debug("idle check path=%s user_id=%s sid=%s", request.path, getattr(current_user, 'id', None), sid)
    if not sid:
        app.logger.debug("Idle timeout: missing sid for user_id=%s", getattr(current_user, 'id', None))
        logout_user()
        session.pop('last_activity', None)
        flash('Your session has expired or was revoked.', 'warning')
        return redirect(url_for('login'))

    last_ts = session.get("last_activity")
    db_last = None
    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT last_activity, login_time FROM user_sessions WHERE session_id = ?", (sid,)).fetchone()
            if row:
                db_last = row["last_activity"] or row["login_time"]
                app.logger.debug("Idle timeout: sid=%s db_last=%s user_id=%s", sid, db_last, getattr(current_user, 'id', None))
    except Exception:
        pass

    if not db_last:
        # No DB row for this session, treat as invalid
        app.logger.debug("Idle timeout: sid %s missing in DB; logging out user_id=%s", sid, getattr(current_user, 'id', None))
        logout_user()
        session.clear()
        flash('Your session has expired or was revoked.', 'warning')
        return redirect(url_for('login'))

    if not last_ts:
        last_ts = db_last
        session["last_activity"] = last_ts

    parsed = _parse_ts_utc(last_ts) or _parse_ts_utc(db_last)
    if parsed and now - parsed > idle_timeout:
        try:
            with sqlite3.connect(app.config["DB_PATH"]) as conn:
                conn.execute("DELETE FROM user_sessions WHERE session_id = ?", (sid,))
                conn.commit()
        except Exception:
            pass
        app.logger.info("Idle timeout exceeded for user_id=%s sid=%s; logging out.", getattr(current_user, 'id', None), sid)
        logout_user()
        session.clear()
        flash('You have been logged out due to inactivity.', 'warning')
        return redirect(url_for('login'))

    # touch activity
    now_str = _now_utc_str()
    session["last_activity"] = now_str
    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            conn.execute("UPDATE user_sessions SET last_activity = ? WHERE session_id = ?", (now_str, sid))
            conn.commit()
    except Exception:
        pass
    app.logger.debug("Idle touch: user_id=%s sid=%s last_activity=%s", getattr(current_user, 'id', None), sid, now_str)




# --- Approve User (Admin Only) ---
@app.route('/approve_user/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('manage_users'))
    from user_models import get_user_by_id
    user = get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('manage_users'))
    if user.status != 'pending':
        flash('User is not pending approval.', 'info')
        return redirect(url_for('manage_users'))
    import sqlite3
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash('User approved and activated.', 'success')
    return redirect(url_for('manage_users'))



# AJAX endpoint to serve server extension config content
@app.route('/get_server_ext_content')
@login_required
def get_server_ext_content():
    name = request.args.get('name')
    if not name or name == 'None':
        return '[ v3_ext ]\n# No additional extensions', 200, {'Content-Type': 'text/plain'}
    server_ext_dir = os.path.join(app.root_path, "pki-misc")
    if name == 'User':
        safe_name = f'server_ext_{current_user.id}.cnf'
    elif name == 'System':
        safe_name = 'server_ext.cnf'
    else:
        safe_name = os.path.basename(name)
    file_path = os.path.join(server_ext_dir, safe_name)
    if not os.path.isfile(file_path):
        return 'File not found', 404
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read(), 200, {'Content-Type': 'text/plain'}



# --- Add User (Admin Only) ---
@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('manage_users'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', 'user')
        email = request.form.get('email', '').strip() or None
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('add_user.html')
        from user_models import get_user_by_username, create_user_db
        if get_user_by_username(username):
            flash('Username already exists.', 'error')
            return render_template('add_user.html')
        user_id = create_user_db(username, password, role, email)
        if user_id:
            flash('User added successfully.', 'success')
            return redirect(url_for('manage_users'))
        else:
            flash('Failed to add user.', 'error')
    return render_template('add_user.html')

# --- Delete User (Admin Only) ---
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('manage_users'))
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('manage_users'))
    from user_models import delete_user_db
    delete_user_db(user_id)
    flash('User deleted successfully.', 'success')
    return redirect(url_for('manage_users'))

# --- Change Role (Admin Only) ---
@app.route('/change_role/<int:user_id>', methods=['POST'])
@login_required
def change_role(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('manage_users'))
    new_role = request.form.get('role')
    if new_role not in ('user', 'admin'):
        flash('Invalid role.', 'error')
        return redirect(url_for('manage_users'))
    from user_models import update_user_role
    update_user_role(user_id, new_role)
    flash('User role updated.', 'success')
    return redirect(url_for('manage_users'))


@app.context_processor
def inject_logged_in_users():
    # Make LOGGED_IN_USERS available to all templates
    with LOGGED_IN_USERS_LOCK:
        return {"LOGGED_IN_USERS": set(LOGGED_IN_USERS)}

@app.route('/manage_users')
@login_required
def manage_users():
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('index'))
    users = get_all_users()
    logged_in_ids = get_logged_in_user_ids()
    idle_map = get_user_idle_map()
    for user in users:
        user['is_logged_in'] = user['id'] in logged_in_ids
        user['auth_source'] = get_auth_source_for_username(user['username'])
        user['idle'] = idle_map.get(user['id'], '') if user['is_logged_in'] else ''
    return render_template('manage_users.html', users=users)


# --- API endpoint for AJAX user table (full user list with login status) ---
@app.route('/api/users')
@login_required
def api_users():
    if not current_user.is_admin():
        return jsonify({'error': 'forbidden'}), 403
    users = get_all_users()
    logged_in_ids = get_logged_in_user_ids()
    idle_map = get_user_idle_map()
    user_list = []
    for user in users:
        user['auth_source'] = get_auth_source_for_username(user['username'])
        user_list.append({
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'email': user.get('email', ''),
            'status': user['status'],
            'is_logged_in': user['id'] in logged_in_ids,
            'auth_source': user.get('auth_source', 'local'),
            'idle': idle_map.get(user['id'], '') if user['id'] in logged_in_ids else ''
        })
    return jsonify({'users': user_list, 'current_user_id': current_user.id})



# Admin-forced logout action
@app.route('/admin_logout/<int:user_id>', methods=['POST'])
@login_required
def admin_logout(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('manage_users'))
    # Remove all sessions for the user
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
    # If admin logs out themselves, also call logout_user()
    if user_id == current_user.id:
        logout_user()
        flash('You have been logged out.', 'success')
        return redirect(url_for('login'))
    else:
        flash('User has been logged out from all sessions.', 'success')
        return redirect(url_for('manage_users'))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        password_confirm = request.form.get("password_confirm", "").strip()
        email = request.form.get("email", "").strip()
        errors = []
        if not username:
            errors.append("Username is required.")
        elif len(username) < 6:
            errors.append("Username must be at least 6 characters.")
        elif len(username) > 20:
            errors.append("Username must not exceed 20 characters.")
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append("Username can only contain letters, numbers, and underscores.")
        if not password:
            errors.append("Password is required.")
        elif len(password) < 6:
            errors.append("Password must be at least 6 characters.")
        if password != password_confirm:
            errors.append("Passwords do not match.")
        if not email:
            errors.append("Email is required.")
        else:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                errors.append("Invalid email format.")
        if not errors:
            existing_user = get_user_by_username(username)
            if existing_user:
                errors.append("Username already exists.")
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("register.html")
        # Check if this is the first user (make them admin)
        import sqlite3
        conn = sqlite3.connect(app.config["DB_PATH"])
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        user_count = cur.fetchone()[0]
        conn.close()
        role = 'admin' if user_count == 0 else 'user'
        user_id = create_user_db(username, password, role, email or None)
        if user_id:
            if role == 'admin':
                flash("Account created successfully! You are the first user and have been granted admin privileges. You can now log in.", "success")
            else:
                flash("Account created and pending approval. Your registration is awaiting administrator review.", "info")
            app.logger.info(f"New user registered: {username} with role: {role}")
            return redirect(url_for('login'))
        else:
            flash("Registration failed. Please try again.", "error")
            return render_template("register.html")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")
        user = get_user_by_username(username)
        if user:
            if user.status == 'deactivated':
                flash("User account is suspended. Contact administrator.", "error")
                app.logger.warning(f"Login attempt for suspended user: {username}")
            elif user.status == 'pending':
                flash("User account is pending approval by administrator.", "error")
                app.logger.warning(f"Login attempt for pending user: {username}")
            elif user.status == 'active' and user.check_password(password):
                login_user(user)
                update_last_login(user.id)
                app.logger.info(f"User {username} logged in")
                return redirect(url_for('index'))
            else:
                flash("Invalid username or password.", "error")
                app.logger.warning(f"Failed login attempt for: {username}")
        else:
            ldap_result = ldap_authenticate(username, password, app.config, app.logger)
            if ldap_result:
                # Auto-provision LDAP users locally as active standard users
                user_id = create_user_db(username, password, role='user', email=ldap_result.get('email'), status='active', auth_source='ldap')
                LDAP_IMPORTED_USERS.add(username.lower())
                LDAP_SOURCE_CACHE[username.lower()] = "ldap"
                user = get_user_by_username(username)
                if user and user.status == 'active':
                    login_user(user)
                    update_last_login(user.id)
                    app.logger.info(f"User {username} authenticated via LDAP and synced to local DB.")
                    return redirect(url_for('index'))
                else:
                    flash("LDAP authentication succeeded but local user could not be activated. Contact administrator.", "error")
                    app.logger.error(f"LDAP auth ok for {username} but local user creation/activation failed.")
            else:
                flash("Invalid username or password.", "error")
                app.logger.warning(f"Failed login attempt for: {username} (local + LDAP)")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    app.logger.info(f"User {current_user.username} logged out")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))




@app.route("/config", methods=["GET", "POST"])
@login_required
def view_config():
    # If already authenticated in THIS session → allow
    if session.get("config_access_granted") is True:
        pass  # proceed to show config

    # If POST: verify secret
    elif request.method == "POST":
        secret = request.form.get("config_secret", "").strip()
        if secret == app.config.get("DELETE_SECRET"):
            session["config_access_granted"] = True
        else:
            flash("Incorrect secret.", "error")
            return redirect("/certs")

    # If GET and not authenticated → block
    else:
        return redirect("/certs")

    # Show config as before
    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = f.read()
    except FileNotFoundError:
        cfg = "# config.ini not found"

    return render_template("config.html", config_text=cfg)




# ---------- Log reading (polling) ----------
from flask import Response, request

def _read_last_lines(path: str, n: int = 300, chunk_size: int = 8192) -> str:
    """
    Efficient-ish tail: read from the end in chunks until we have N lines.
    Returns UTF-8 text.
    """
    if not os.path.exists(path):
        return "(log file not found)\n"

    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            if end == 0:
                return ""  # empty file

            buffer = b""
            lines = []
            pos = end

            while pos > 0 and len(lines) <= n:
                read_size = min(chunk_size, pos)
                pos -= read_size
                f.seek(pos)
                chunk = f.read(read_size)
                buffer = chunk + buffer
                lines = buffer.splitlines()

            # Take last n lines
            out = b"\n".join(lines[-n:])
            return out.decode("utf-8", errors="replace")
    except Exception as e:
        return f"(failed to read log: {e})\n"

@app.route("/logs/last")
def logs_last():
    """
    Poll this endpoint to get the last N lines of the server log.
    Example: GET /logs/last?n=500
    """
    n = request.args.get("n", default=300, type=int)
    n = max(1, min(n, 5000))  # safety clamp
    text = _read_last_lines(app.config.get("LOG_FILE"), n=n)
    resp = Response(text, mimetype="text/plain; charset=utf-8")
    # avoid caches so polling always fetches fresh data
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/logs")
@login_required
def view_logs_page():
    return render_template("logs.html")




@app.route("/")
@app.route("/certs")
@login_required
def index():
    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            cur = conn.cursor()
            if current_user.is_admin():
                cur.execute("""
                    SELECT c.id, c.subject, c.serial, c.revoked, c.cert_pem, c.user_id
                    FROM certificates c
                """)
            else:
                cur.execute("""
                    SELECT c.id, c.subject, c.serial, c.revoked, c.cert_pem, c.user_id
                    FROM certificates c
                    WHERE c.user_id = ?
                """, (current_user.id,))
            rows = cur.fetchall()
        #app.logger.debug(f"DB retruned {len(rows)} certificates for user {current_user.username}    (id={current_user.id})")
        certs = []
        now = datetime.now(timezone.utc)
        from user_models import get_user_by_id
        for row in rows:
            # Now expecting 6 columns: id, subject, serial, revoked, cert_pem, user_id
            id_, subject, serial, revoked, cert_pem, user_id = row
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(), default_backend()
            )
            issue_date = cert.not_valid_before_utc.astimezone().strftime("%Y-%m-%d %H:%M")
            expired = cert.not_valid_after_utc < now
            keycol = extract_keycol_with_openssl(
                cert.public_bytes(Encoding.PEM).decode("utf-8").encode("utf-8")
            )
            username = None
            if user_id:
                user_obj = get_user_by_id(user_id)
                username = user_obj.username if user_obj else str(user_id)
            app.logger.debug(f"Cert ID {id_}: keycol={keycol}, expired={expired}   revoked={revoked}")
            certs.append((id_, subject, serial, keycol, issue_date, revoked, expired, username))

        return render_template(
            "list_certificates.html",
            certs=certs,
            is_admin=current_user.is_admin()
        )
    except Exception as e:
        app.logger.error(f"Failed to load index: {e}")
        return f"Error: {e}", 500


@app.route("/sign")
@login_required
def sign():
    try:
        # 1) Fetch raw rows
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            if hasattr(current_user, 'is_admin') and current_user.is_admin():
                csr_requests = conn.execute(
                    "SELECT id, name, csr_pem, created_at FROM csrs"
                ).fetchall()
            else:
                csr_requests = conn.execute(
                    "SELECT id, name, csr_pem, created_at FROM csrs WHERE user_id = ?",
                    (current_user.id,)
                ).fetchall()

        # validity setting
        try:
            with open(app.config["VALIDITY_CONF"], "r") as f:
                validity_days = f.read().strip()
        except FileNotFoundError:
            validity_days = "365"

        # List available server extension configs from pki-misc
        # Use app.root_path for compatibility (Flask always sets this)
        server_ext_dir = os.path.join(app.root_path, "pki-misc")
        ext_files = [f for f in os.listdir(server_ext_dir) if f.endswith('.cnf')]
        server_ext_options = ["None"]
        user_ext = f"server_ext_{current_user.id}.cnf"
        if "server_ext.cnf" in ext_files:
            server_ext_options.append("System")
        if user_ext in ext_files:
            server_ext_options.append("User")

        return render_template(
            "sign.html",
            csr_requests=csr_requests,
            server_ext_options=server_ext_options,
            validity_days=validity_days
        )

    except Exception as e:
        app.logger.error(f"Failed to load index: {e}")
        return f"Error: {e}", 500




@app.route('/load_profile', methods=['GET'])
def load_profile():
    filename = request.args.get('filename')
    if not filename:
        return "Filename not provided", 400

    absolute_path = os.path.join(app.root_path, X509_PROFILE_DIR, filename)
    #app.logger.debug(f"Looking for profile configuration at: {absolute_path}")

    if not os.path.exists(absolute_path):
        return "File not found", 404
    with open(absolute_path, "r") as f:
        content = f.read()
    return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}

# ---------- Inspect Endpoint ----------

# Available types and their openssl subcommands
DER_TYPES = [
    ("Certificate Signing Request",   ["req",   "-noout", "-text"]),
    ("X.509 Certificate",             ["x509",  "-noout", "-text"]),
    ("Certificate Revocation List",    ["crl",   "-noout", "-text"]),
    ("PKCS#7 / CMS",                   ["pkcs7", "-print_certs", "-noout", "-text"]),
    ("PKCS#12 / PFX",                  ["pkcs12","-info", "-nodes", "-in"]),
    ("OCSP Request",                   ["ocsp",  "-reqin"]),
    ("OCSP Response",                  ["ocsp",  "-respin"]),
    ("Private Key",                    []),  # special case using openssl pkey
    ("Public Key",                     []),  # openssl pkey -pubin
]


@app.route("/inspect", methods=["GET", "POST"])
@login_required
def inspect():
    result = None

    if request.method == "POST":
        data = request.form.get("inspect_data", "").strip()

        if not data:
            result = "No data provided."

        else:
            is_pem = data.startswith("-----BEGIN ")

            # ─── Non‑PEM: auto‑detect by trying every DER_TYPE ───
            if not is_pem:
                # Decode Base64 → DER bytes
                try:
                    der_bytes = base64.b64decode(data)
                except Exception:
                    result = "Failed to base64-decode input."
                    return render_template("inspect.html", result=result)

                # Write DER to temp file
                fd, path = tempfile.mkstemp(suffix=".der")
                os.close(fd)
                with open(path, "wb") as f:
                    f.write(der_bytes)

                detected = None
                detected_cmd = None
                detected_out = None
                failures = []

                for label, subcmd in DER_TYPES:
                    # Build the command, injecting -noout on generic DER
                    if label == "Private Key":
                        cmd = ["openssl", "pkey", "-inform DER", "-in", path, "-noout", "-text"]

                    elif label == "Public Key":
                        cmd = ["openssl", "pkey", "-pubin", "-in", path, "-noout", "-text"]

                    elif label == "OCSP Request":
                        cmd = ["openssl", "ocsp", "-reqin", path, "-text", "-noverify"]

                    elif label == "OCSP Response":
                        cmd = ["openssl", "ocsp", "-respin", path, "-text", "-noverify"]

                    elif label == "PKCS#12 / PFX":
                        cmd = ["openssl"] + subcmd + [path]

                    else:
                        # Generic DER handler: add -noout after -inform DER
                        cmd = ["openssl", subcmd[0], "-inform", "DER", "-noout", "-in", path] + subcmd[1:]

                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    out = proc.stdout.strip() or proc.stderr.strip()

                    if proc.returncode == 0:
                        detected = label
                        detected_cmd = cmd
                        detected_out = out
                        break
                    else:
                        failures.append((label, cmd, proc.returncode, out))

                os.remove(path)

                if detected:
                    header = f"Detected as: {detected}"
                    cmd_line = f"$ {' '.join(detected_cmd)}"
                    result = "\n".join([header, cmd_line, detected_out])
                else:
                    # None succeeded: show all failures
                    lines = ["None of the DER options succeeded. Debug info:"]
                    for lbl, cmd, code, out in failures:
                        lines.append(f"--- {lbl} (exit {code}) ---")
                        lines.append(f"$ {' '.join(cmd)}")
                        lines.append(out or "(no output)")
                        lines.append("")
                    result = "\n".join(lines)

            # ─── PEM: use your existing “chosen” dispatch logic ───
            else:
                # 1) Write to temp .pem
                fd, path = tempfile.mkstemp(suffix=".pem")
                os.close(fd)
                with open(path, "wb") as f:
                    f.write(data.encode())

                # 2) Auto-detect PEM header to set `chosen`
                hdr = data.splitlines()[0].strip()
                if hdr.startswith("-----BEGIN PRIVATE KEY") \
                   or hdr.startswith("-----BEGIN RSA PRIVATE KEY") \
                   or hdr.startswith("-----BEGIN EC PRIVATE KEY"):
                    chosen = "Private Key"
                elif hdr.startswith("-----BEGIN PUBLIC KEY"):
                    chosen = "Public Key"
                elif hdr.startswith("-----BEGIN OCSP REQUEST"):
                    chosen = "OCSP Request"
                elif hdr.startswith("-----BEGIN OCSP RESPONSE"):
                    chosen = "OCSP Response"
                elif hdr.startswith("-----BEGIN CERTIFICATE REQUEST"):
                    chosen = "Certificate Signing Request"
                elif hdr.startswith("-----BEGIN CERTIFICATE"):
                    chosen = "X.509 Certificate"
                elif hdr.startswith("-----BEGIN X509 CRL") or hdr.startswith("-----BEGIN CRL"):
                    chosen = "Certificate Revocation List"
                elif hdr.startswith("-----BEGIN PKCS7") or hdr.startswith("-----BEGIN CMS"):
                    chosen = "PKCS#7 / CMS"
                elif hdr.startswith("-----BEGIN PKCS12") or path.lower().endswith((".p12", ".pfx")):
                    chosen = "PKCS#12 / PFX"
                else:
                    chosen = "X.509 Certificate"

                # 3) Find the command template
                subcmd = next(cmd for (lbl, cmd) in DER_TYPES if lbl == chosen)

                # 4) Dispatch *exactly* as you had it, but add -noout on non‑PEM OCSP
                if chosen == "Private Key":
                    cmd = ["openssl", "pkey", "-in", path, "-noout", "-text"]
                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    out, err = proc.stdout, proc.stderr

                elif chosen == "Public Key":
                    cmd = ["openssl", "pkey", "-pubin", "-in", path, "-noout", "-text"]
                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    out, err = proc.stdout, proc.stderr

                elif chosen == "OCSP Response":
                    # both PEM & DER now use -noout
                    cmd = ["openssl", "ocsp", "-respin", path, "-noout", "-text", "-noverify"]
                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    out, err = proc.stdout, proc.stderr

                elif chosen == "OCSP Request":
                    cmd = ["openssl", "ocsp", "-reqin", path, "-noout", "-text", "-noverify"]
                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    out, err = proc.stdout, proc.stderr

                elif chosen == "PKCS#12 / PFX":
                    cmd = ["openssl", *subcmd, path]
                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    out, err = proc.stdout, proc.stderr

                else:
                    # generic PEM handler
                    cmd = ["openssl", *subcmd, "-in", path]
                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    out, err = proc.stdout, proc.stderr

                os.remove(path)

                header = f"Detected: {chosen}"
                cmd_line = f"$ {' '.join(cmd)}"
                body = out.strip() or err.strip()
                result = "\n".join([header, cmd_line, body])

    return render_template("inspect.html",
                           result=result,
                           der_types=[lbl for lbl, _ in DER_TYPES])



def inspectM():
    result = None
    der_mode = False
    pending_data = ""

    if request.method == "POST":
        data = request.form.get("inspect_data", "").strip()
        chosen = request.form.get("der_type")

        if not data:
            result = "No data provided."
        else:
            is_pem = data.startswith("-----BEGIN ")
            if not is_pem and not chosen:
                der_mode = True
                pending_data = data
            else:
                fd, path = tempfile.mkstemp(suffix=(".pem" if is_pem else ".der"))
                try:
                    with os.fdopen(fd, "wb") as f:
                        if is_pem:
                            f.write(data.encode())
                        else:
                            f.write(base64.b64decode(data))

                    # Auto-detect PEM header
                    if is_pem:
                        hdr = data.splitlines()[0].strip()
                        if hdr.startswith("-----BEGIN PRIVATE KEY") or hdr.startswith("-----BEGIN RSA PRIVATE KEY") or hdr.startswith("-----BEGIN EC PRIVATE KEY"):
                            chosen = "Private Key"
                        elif hdr.startswith("-----BEGIN PUBLIC KEY"):
                            chosen = "Public Key"
                        elif hdr.startswith("-----BEGIN OCSP REQUEST"):
                            chosen = "OCSP Request"
                        elif hdr.startswith("-----BEGIN OCSP RESPONSE"):
                            chosen = "OCSP Response"
                        elif hdr.startswith("-----BEGIN CERTIFICATE REQUEST"):
                            chosen = "Certificate Signing Request"
                        elif hdr.startswith("-----BEGIN CERTIFICATE"):
                            chosen = "X.509 Certificate"
                        elif hdr.startswith("-----BEGIN X509 CRL") or hdr.startswith("-----BEGIN CRL"):
                            chosen = "Certificate Revocation List"
                        elif hdr.startswith("-----BEGIN PKCS7") or hdr.startswith("-----BEGIN CMS"):
                            chosen = "PKCS#7 / CMS"
                        elif hdr.startswith("-----BEGIN PKCS12") or path.lower().endswith((".p12", ".pfx")):
                            chosen = "PKCS#12 / PFX"
                        else:
                            chosen = "X.509 Certificate"

                    # Find command template
                    subcmd = next(cmd for (lbl, cmd) in DER_TYPES if lbl == chosen)

                    # Dispatch
                    if chosen == "Private Key":
                        cmd = ["openssl", "pkey", "-in", path, "-noout", "-text"]
                        proc = subprocess.run(cmd, capture_output=True, text=True)
                        out, err = proc.stdout, proc.stderr

                    elif chosen == "Public Key":
                        cmd = ["openssl", "pkey", "-pubin", "-in", path, "-noout", "-text"]
                        proc = subprocess.run(cmd, capture_output=True, text=True)
                        out, err = proc.stdout, proc.stderr

                    elif chosen == "OCSP Response":
                        if is_pem:
                            cmd = ["openssl", "ocsp", "-respin", path, "-noout", "-text", "-noverify"]
                            proc = subprocess.run(cmd, capture_output=True, text=True)
                            out, err = proc.stdout, proc.stderr
                        else:
                            der = base64.b64decode(data)
                            cmd = ["openssl", "ocsp", "-respin", "-", "-text", "-noverify"]
                            proc = subprocess.run(cmd, input=der, capture_output=True)
                            out = proc.stdout.decode("utf-8", errors="ignore")
                            err = proc.stderr.decode("utf-8", errors="ignore")

                    elif chosen == "OCSP Request":
                        if is_pem:
                            cmd = ["openssl", "ocsp", "-reqin", path, "-noout", "-text", "-noverify"]
                            proc = subprocess.run(cmd, capture_output=True, text=True)
                            out, err = proc.stdout, proc.stderr
                        else:
                            der = base64.b64decode(data)
                            cmd = ["openssl", "ocsp", "-reqin", "-", "-text", "-noverify"]
                            proc = subprocess.run(cmd, input=der, capture_output=True)
                            out = proc.stdout.decode("utf-8", errors="ignore")
                            err = proc.stderr.decode("utf-8", errors="ignore")

                    elif chosen == "PKCS#12 / PFX":
                        cmd = ["openssl", *subcmd, path]
                        proc = subprocess.run(cmd, capture_output=True, text=True)
                        out, err = proc.stdout, proc.stderr

                    else:
                        if is_pem:
                            cmd = ["openssl", *subcmd, "-in", path]
                        else:
                            cmd = ["openssl", subcmd[0], "-inform", "DER", "-in", path] + subcmd[1:]
                        proc = subprocess.run(cmd, capture_output=True, text=True)
                        out, err = proc.stdout, proc.stderr

                    header = f"Detected: {chosen}"
                    cmd_line = f"$ {' '.join(cmd)}"
                    body = out.strip() or err.strip()
                    result = "\n".join([header, cmd_line, body])

                except Exception as e:
                    result = f"Failed to inspect: {e}"
                finally:
                    try: os.remove(path)
                    except OSError:
                        pass

    return render_template(
        "inspect.html",
        result=result,
        der_mode=der_mode,
        pending_data=pending_data,
        der_types=[lbl for lbl, _ in DER_TYPES]
    )


# ---------- APIs Endpoint ----------

@app.route("/api")
@login_required
def api_doc():
    return render_template("api.html")


# ---------- Validity Endpoint ----------

@app.route("/update_validity", methods=["POST"])
def update_validity():
    new_validity = request.form.get("validity_days", "365").strip()
    try:
        with open(app.config["VALIDITY_CONF"], "w") as f:
            f.write(new_validity)
        flash("Validity period updated to " + new_validity + " days", "success")
    except Exception as e:
        flash("Error updating validity period: " + str(e), "error")
    return redirect("/")


# ---------- VA enpoint ----------  

@app.route("/va")
@login_required
def va_page():
    try:
        # Read the CRL content from the file defined by CRL_PATH.
        with open(app.config["CRL_PATH"], "rb") as f:
            crl_data = f.read().decode("utf-8")
        
        # Run the OpenSSL command to get the raw CRL details.
        proc = subprocess.Popen(
            ["openssl", "crl", "-noout", "-text", "-in", app.config["CRL_PATH"] ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            raw_crl_output = "Error: " + stderr.decode("utf-8")
        else:
            raw_crl_output = stdout.decode("utf-8")
        
        # Query the database for all revoked certificates (revoked flag = 1)
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            revoked = conn.execute("SELECT id, subject, serial FROM certificates WHERE revoked = 1").fetchall()
        
        return render_template("va.html", 
                               crl_content=crl_data, 
                               raw_crl=raw_crl_output, 
                               revoked_certificates=revoked)
    except Exception as e:
        app.logger.error(f"Error in /va endpoint: {str(e)}")
        return f"Error loading VA data: {str(e)}", 500


# ---------- CA enpoint ----------


@app.route("/ca")
@login_required
def ca_page():
    try:
        # Load the Root CA certificate
        with open(app.config["ROOT_CERT_PATH"], "r") as f:
            root_cert_pem = f.read()
        root_cert = x509.load_pem_x509_certificate(root_cert_pem.encode(), default_backend())
        root_cert_details = certificate_to_dict(root_cert)
        root_raw_cert = root_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        root_cert_text = get_certificate_text(root_cert_pem)
        
        # Load the Subordinate CA certificate
        with open(app.config["SUBCA_CERT_PATH"], "r") as f:
            sub_cert_pem = f.read()
        sub_cert = x509.load_pem_x509_certificate(sub_cert_pem.encode(), default_backend())
        sub_cert_details = certificate_to_dict(sub_cert)
        sub_raw_cert = sub_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        sub_cert_text = get_certificate_text(sub_cert_pem)
        
        return render_template("ca.html", 
                               root_cert_details=root_cert_details, root_raw_cert=root_raw_cert, root_cert_text=root_cert_text,
                               sub_cert_details=sub_cert_details, sub_raw_cert=sub_raw_cert, sub_cert_text=sub_cert_text)
    except Exception as e:
        app.logger.error(f"Error loading CA certificates: {str(e)}")
        return f"Error loading CA certificates: {str(e)}", 500



@app.route("/server_ext", methods=["GET", "POST"])
@login_required
def server_ext():
    user_ext_path = os.path.join(app.root_path, "pki-misc", f"server_ext_{current_user.id}.cnf")
    system_ext_path = app.config["SERVER_EXT_PATH"]
    # Load user default if exists, else system default
    if os.path.exists(user_ext_path):
        with open(user_ext_path, "r", encoding="utf-8") as f:
            manual_config = f.read()
    else:
        try:
            with open(system_ext_path, "r", encoding="utf-8") as f:
                manual_config = f.read()
        except FileNotFoundError:
            manual_config = ""
    if request.method == "POST":
        new_config = request.form.get("server_ext_config") or ""
        save_system = request.form.get("save_system_default") == "on"
        # Validate config using _validate_cnf from x509_profiles.py
        import tempfile
        from x509_profiles import _validate_cnf
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".cnf", encoding="utf-8") as tmpf:
            tmpf.write(new_config)
            tmp_path = tmpf.name
        is_valid, msg = _validate_cnf(tmp_path)
        os.unlink(tmp_path)
        if not is_valid:
            flash(f"Configuration validation failed: {msg}", "danger")
            manual_config = new_config  # repopulate form with attempted config
        else:
            # Always save user default
            with open(user_ext_path, "w", encoding="utf-8", newline='') as f:
                f.write(new_config)
            if save_system:
                with open(system_ext_path, "w", encoding="utf-8", newline='') as f:
                    f.write(new_config)
                flash("Configuration saved as both user and system default.", "success")
            else:
                flash("Configuration saved as your user default.", "success")
            return redirect(url_for("server_ext"))
    if current_user.is_admin():
        profiles = Profile.query.order_by(Profile.id.desc()).all()
    else:
        profiles = Profile.query.filter_by(user_id=current_user.id).order_by(Profile.id.desc()).all()
    return render_template("server_ext.html", server_ext_config=manual_config, profiles=profiles)

@app.route("/view_root")
def view_root():
    try:
        with open(app.config["ROOT_CERT_PATH"], "r") as f:
            cert_pem = f.read()
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        cert_details = certificate_to_dict(cert)
        raw_cert = cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")
        cert_text = get_certificate_text(raw_cert)
        return render_template("view.html", cert_details=cert_details, raw_cert=raw_cert, cert_text=cert_text)
    except Exception as e:
        app.logger.error(f"Failed to view root certificate: {str(e)}")
        return f"Failed to view root certificate: {str(e)}", 500

@app.route("/view_sub")
def view_sub():
    try:
        with open(app.config["SUBCA_CERT_PATH"], "r") as f:
            cert_pem = f.read()
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        cert_details = certificate_to_dict(cert)
        raw_cert = cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")
        cert_text = get_certificate_text(raw_cert)
        return render_template("view.html", cert_details=cert_details, raw_cert=raw_cert, cert_text=cert_text)
    except Exception as e:
        app.logger.error(f"Failed to view subordinate certificate: {str(e)}")
        return f"Failed to view subordinate certificate: {str(e)}", 500

@app.route("/view/<int:cert_id>")
@login_required
def view_certificate(cert_id):
    app.logger.debug(f"view_certificate called with cert_id={cert_id}")
    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            conn.row_factory = sqlite3.Row
            if current_user.is_admin():
                cur = conn.execute(
                    "SELECT id, subject, serial, revoked, cert_pem FROM certificates WHERE id = ?",
                    (cert_id,)
                )
            else:
                cur = conn.execute(
                    "SELECT id, subject, serial, revoked, cert_pem FROM certificates WHERE id = ? AND user_id = ?",
                    (cert_id, current_user.id)
                )
            row = cur.fetchone()
            app.logger.debug(f"DB row for id={cert_id}: {row!r}")

        if not row:
            return f"Certificate not found or access denied (tried id={cert_id})", 404

        cert_pem = row["cert_pem"]
        app.logger.debug("Loaded PEM, length=%d", len(cert_pem))
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"), default_backend())
        cert_details = certificate_to_dict(cert)
        raw_cert = cert.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode("utf-8")
        cert_text = get_certificate_text(raw_cert)
        return render_template(
            "view.html",
            cert_details=cert_details,
            raw_cert=raw_cert,
            cert_text=cert_text
        )
    except Exception as e:
        app.logger.exception("Failed to view certificate")
        return f"Failed to view certificate: {e}", 500



@app.route("/status/<serial>")
def cert_status(serial):
    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            row = conn.execute("SELECT revoked FROM certificates WHERE serial = ?", (serial,)).fetchone()
            if row:
                return {"serial": serial, "status": "revoked" if row[0] else "valid"}
        return {"serial": serial, "status": "not found"}, 404
    except Exception as e:
        app.logger.error(f"Failed to check certificate status: {str(e)}")
        return f"Status check failed: {str(e)}", 500

@app.route("/expired")
def expired_certs():
    try:
        expired = []
        now = datetime.datetime.utcnow()
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            rows = conn.execute("SELECT id, cert_pem FROM certificates").fetchall()
            for row in rows:
                cert = x509.load_pem_x509_certificate(row[1].encode())
                if cert.not_valid_after < now:
                    expired.append(row[0])
        return {"expired_cert_ids": expired}
    except Exception as e:
        app.logger.error(f"Failed to retrieve expired certificates: {str(e)}")
        return f"Expired certs check failed: {str(e)}", 500



@app.route("/delete/<int:cert_id>", methods=["POST"])
@login_required
def delete_certificate(cert_id):
    # Get the secret from the form and normalize it a bit
    secret = request.form.get("delete_secret", "").strip()
    expected = str(app.config.get("DELETE_SECRET", "")).strip()

#    app.logger.info(f"[DELETE] Request to delete cert {cert_id}, "
#                    f"provided_secret_len={len(secret)} given {secret} expected {expected}")

    # Secret mismatch → log and go back to /certs
    if secret != expected:
        app.logger.warning(f"[DELETE] Wrong delete secret for certificate ID {cert_id}")
        return redirect("/certs")

    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            if current_user.is_admin():
                cur = conn.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
            else:
                cur = conn.execute("DELETE FROM certificates WHERE id = ? AND user_id = ?", (cert_id, current_user.id))
            conn.commit()
            app.logger.info(f"[DELETE] Rows deleted for cert {cert_id}: {cur.rowcount}")
    except Exception as e:
        app.logger.error(f"[DELETE] Failed to delete certificate ID {cert_id}: {str(e)}")

    # Always back to /certs (success or failure)
    return redirect("/certs")




@app.route("/submit", methods=["POST"])
@login_required
def submit():
    csr_pem = request.form["csr"]
    ext_block = request.form.get("ext_block", "v3_ext")
    try:
        csr_obj = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        subject_str = ", ".join([f"{attr.oid._name}={attr.value}" for attr in csr_obj.subject])
    except Exception as e:
        subject_str = "Unknown Subject"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csr") as csr_file:
        csr_file.write(csr_pem.encode())
        csr_filename = csr_file.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
        cert_filename = cert_file.name

    custom_serial = secrets.randbits(64)
    # Format it as a hexadecimal string (with the 0x prefix)
    custom_serial_str = hex(custom_serial)


    # Read the validity period from the validity.conf file
    try:
        with open(app.config["VALIDITY_CONF"], "r") as f:
            validity_days = f.read().strip()
    except FileNotFoundError:
        validity_days = "365"  # fallback if not set

    try:
        cmd = ["openssl", "x509"]
        cmd.extend(get_provider_args())
        cmd.extend(["-req",
            "-in", csr_filename,
            "-CA", app.config["SUBCA_CERT_PATH"],
            "-CAkey", app.config["SUBCA_KEY_PATH"],
            "-set_serial", custom_serial_str, 
            "-CAcreateserial",
            "-days", validity_days,
            "-out", cert_filename,
            "-extfile", app.config["SERVER_EXT_PATH"],
            "-extensions", ext_block
        ])
        #app.logger.debug("Running OpenSSL command: %s", " ".join(cmd))
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        os.unlink(csr_filename)
        os.unlink(cert_filename)
        error_msg = f"Error during OpenSSL signing: {e.stderr}"
        app.logger.error(error_msg)
        flash(error_msg, "error")
        return redirect("/")
    with open(cert_filename, "r") as f:
        cert_pem = f.read()
    cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    actual_serial = hex(cert_obj.serial_number)
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute("INSERT INTO certificates (subject, serial, cert_pem, user_id) VALUES (?, ?, ?, ?)",
                     (subject_str, actual_serial, cert_pem, current_user.id))
    os.unlink(csr_filename)
    os.unlink(cert_filename)
    return redirect("/")

@app.route("/submit_q", methods=["POST"])
def submit_q():
    csr_pem = request.form["csr"]
    ext_block = request.form.get("ext_block", "v3_ext")
    try:
        csr_obj = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        subject_str = ", ".join([f"{attr.oid._name}={attr.value}" for attr in csr_obj.subject])
    except Exception as e:
        subject_str = "Unknown Subject"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csr") as csr_file:
        csr_file.write(csr_pem.encode())
        csr_filename = csr_file.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
        cert_filename = cert_file.name

    custom_serial = secrets.randbits(64)
    # Format it as a hexadecimal string (with the 0x prefix)
    custom_serial_str = hex(custom_serial)


    # Read the validity period from the validity.conf file
    try:
        with open(app.config["VALIDITY_CONF"], "r") as f:
            validity_days = f.read().strip()
    except FileNotFoundError:
        validity_days = "365"  # fallback if not set

    try:
        cmd = ["openssl", "x509"]
        cmd.extend(get_provider_args())
        cmd.extend(["-req",
            "-in", csr_filename,
            "-CA", app.config["SUBCA_CERT_PATH"],
            "-signkey", app.config["SUBCA_KEY_PATH"],
            "-set_serial", custom_serial_str,
            "-CAcreateserial",
            "-days", validity_days,
            "-out", cert_filename,
            "-extfile", app.config["SERVER_EXT_PATH"],
            "-extensions", ext_block
        ])
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        os.unlink(csr_filename)
        os.unlink(cert_filename)
        app.logger.error("Error during OpenSSL signing: %s", e.stderr)
        return "Error signing CSR", 500
    with open(cert_filename, "r") as f:
        cert_pem = f.read()
    full_chain_pem = cert_pem
    if os.path.exists(app.config["CHAIN_FILE_PATH"]):
        with open(app.config["CHAIN_FILE_PATH"], "r") as f:
            full_chain_pem += f.read()
    serial_hex = hex(x509.random_serial_number())
    from flask_login import current_user
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute("INSERT INTO certificates (subject, serial, cert_pem, user_id) VALUES (?, ?, ?, ?)",
                     (subject_str, serial_hex, full_chain_pem, current_user.id))
    os.unlink(csr_filename)
    os.unlink(cert_filename)
    return redirect("/")


@app.route("/revoke/<int:cert_id>", methods=["POST"])
@login_required
def revoke(cert_id):
    secret = request.form.get("delete_secret", "").strip()
    expected = str(app.config.get("DELETE_SECRET", "")).strip()
    if secret != expected:
        app.logger.warning(f"[REVOKE] Wrong delete secret for certificate ID {cert_id}")
        return redirect("/certs")
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        if current_user.is_admin():
            conn.execute("UPDATE certificates SET revoked = 1 WHERE id = ?", (cert_id,))
        else:
            conn.execute("UPDATE certificates SET revoked = 1 WHERE id = ? AND user_id = ?", (cert_id, current_user.id))
        conn.commit()
        app.logger.info(f"[REVOKE] Certificate {cert_id} revoked.")
    update_crl()
    return redirect("/certs")





#@app.route("/revoke/<int:cert_id>")

def revokeY(cert_id):
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute("UPDATE certificates SET revoked = 1 WHERE id = ?", (cert_id,))
        conn.commit()
    # Immediately update the CRL file.
    update_crl()
    return redirect("/")

def revokeX(cert_id):
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute("UPDATE certificates SET revoked = 1 WHERE id = ?", (cert_id,))
    return redirect("/")



# ---------- ZIP Download Endpoint ----------
@app.route("/downloads/all_zip")
def download_all_zip():
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            rows = conn.execute("SELECT id, cert_pem FROM certificates").fetchall()
            for row in rows:
                filename = f"cert_{row[0]}.pem"
                zf.writestr(filename, row[1])
    mem_zip.seek(0)
    return send_file(mem_zip, as_attachment=True, download_name="all_certificates.zip", mimetype="application/zip")

def update_crl():
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    # Load the CA certificate and key.
    with open(app.config["SUBCA_CERT_PATH"], "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(app.config["SUBCA_KEY_PATH"], "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    now = datetime.datetime.utcnow()
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(now + datetime.timedelta(days=7))
    
    # Get revoked certificates from the DB.
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        rows = conn.execute("SELECT serial FROM certificates WHERE revoked = 1").fetchall()
        for row in rows:
            serial = int(row[0], 16)
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(now)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)
    
    crl_obj = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    with open(app.config["CRL_PATH"], "wb") as f:
        f.write(crl_obj.public_bytes(serialization.Encoding.PEM))
    return crl_obj




@app.route("/downloads/crl")
def crl():
    return send_file(app.config["CRL_PATH"], as_attachment=True)


@app.route("/downloads/<int:cert_id>")
def download(cert_id):
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        row = conn.execute("SELECT cert_pem FROM certificates WHERE id = ?", (cert_id,)).fetchone()
    if row:
        cert_pem = row[0]
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            common_name = None
            for attribute in cert.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    common_name = attribute.value
                    break
            filename = f"{common_name.replace(' ', '')}.pem" if common_name else f"cert_{cert_id}.pem"
        except Exception as e:
            filename = f"cert_{cert_id}.pem"
        response = make_response(cert_pem)
        response.headers.set("Content-Type", "application/x-pem-file")
        response.headers.set("Content-Disposition", "attachment", filename=filename)
        return response
    return "Certificate not found", 404

@app.route("/downloads/chain")
def download_chain():
    return send_file(app.config["CHAIN_FILE_PATH"], as_attachment=True, download_name="chain.cert.pem")

# ---------- SCEP Endpoint ----------

# using scep blueprint instead 



# ---------- OCSPV Endpoint ----------


from cryptography.x509.ocsp import (
    load_der_ocsp_request,
    OCSPResponseBuilder,
    OCSPResponderEncoding,
    OCSPCertStatus,
    OCSPResponseStatus,
)
from cryptography.x509.oid import ExtensionOID


@app.route("/ocspv", methods=["POST", "GET"])
def ocspv():
    app.logger.debug("OCSP endpoint called.")
    try:
        # 1) Fetch raw request
        if request.method == "GET":
            b64_req = request.args.get("ocsp")
            if not b64_req:
                raise ValueError("No OCSP request found in query param")
            request_data = base64.b64decode(b64_req)
        else:
            request_data = request.data
            if not request_data:
                raise ValueError("Empty OCSP request body")

        # 2) First parse with cryptography (never breaks on version field)
        ocsp_req = load_der_ocsp_request(request_data)
        requests_serials = [ocsp_req.serial_number]

        # 2b) Try to extract *additional* requests with asn1crypto
        try:
            asn1_req = asn1_ocsp.OCSPRequest.load(request_data)
            req_list = asn1_req['tbs_request']['request_list']

            if len(req_list) > 1:
                requests_serials = []
                for single in req_list:
                    sn = single['req_cert']['serial_number'].native
                    requests_serials.append(sn)
        except Exception:
            pass  # ignore, we already have the first request

        # 3) Load CA
        with open(app.config["SUBCA_CERT_PATH"], "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(app.config["SUBCA_KEY_PATH"], "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        now = dt.datetime.utcnow()
        next_update = now + dt.timedelta(days=7)
        builder = OCSPResponseBuilder()

        # 4) Process each serial number
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            for sn in requests_serials:
                row = conn.execute(
                    "SELECT cert_pem, revoked FROM certificates WHERE serial = ?",
                    (hex(sn),),
                ).fetchone()

                if not row:
                    ocsp_resp = OCSPResponseBuilder.build_unsuccessful(
                        OCSPResponseStatus.UNAUTHORIZED
                    )
                    return make_response(
                        ocsp_resp.public_bytes(serialization.Encoding.DER),
                        200,
                        {"Content-Type": "application/ocsp-response"},
                    )

                cert_pem, revoked_flag = row
                target_cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                revoked = (revoked_flag == 1)

                builder = builder.add_response(
                    cert=target_cert,
                    issuer=ca_cert,
                    algorithm=hashes.SHA1(),
                    cert_status=OCSPCertStatus.REVOKED if revoked else OCSPCertStatus.GOOD,
                    this_update=now,
                    next_update=next_update,
                    revocation_time=now if revoked else None,
                    revocation_reason=x509.ReasonFlags.unspecified if revoked else None,
                )

        # 5) Responder ID
        builder = builder.responder_id(OCSPResponderEncoding.HASH, ca_cert)

        # 6) Copy nonce (cryptography API works)
        try:
            for ext in ocsp_req.extensions:
                if ext.oid == ExtensionOID.OCSP_NONCE:
                    builder = builder.add_extension(ext, critical=False)
                    break
        except Exception:
            pass

        # 7) Sign
        ocsp_response = builder.sign(private_key, hashes.SHA256())

        return make_response(
            ocsp_response.public_bytes(serialization.Encoding.DER),
            200,
            {"Content-Type": "application/ocsp-response"},
        )

    except Exception as e:
        app.logger.error(f"OCSP request processing failed: {str(e)}")
        return f"OCSP request processing failed: {str(e)}", 400




# ---------- OCSP Endpoint ----------




from asn1crypto import ocsp as asn1_ocsp
import datetime as dt


@app.route("/ocsp", methods=["POST", "GET"])
def ocsp():
    app.logger.debug("OCSP endpoint called.")
    try:
        # 1) Get DER OCSP request (POST body) or base64 (?ocsp=...) for GET
        if request.method == "GET":
            b64_req = request.args.get("ocsp")
            if not b64_req:
                raise ValueError("No OCSP request found in query param")
            request_data = base64.b64decode(b64_req)
        else:
            request_data = request.data
            if not request_data:
                raise ValueError("Empty OCSP request body")

        # 2) Parse with asn1crypto so we can see ALL requests
        asn1_req = asn1_ocsp.OCSPRequest.load(request_data)
        tbs_req = asn1_req["tbs_request"]
        req_list = tbs_req["request_list"]

        # 3) Load issuer (CA) and key once
        with open(app.config["SUBCA_CERT_PATH"], "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        with open(app.config["SUBCA_KEY_PATH"], "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        now = dt.datetime.utcnow()
        next_update = now + dt.timedelta(days=7)

        builder = OCSPResponseBuilder()

        # 4) Add a SingleResponse for each request in the OCSPRequest
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            for single_req in req_list:
                req_cert = single_req["req_cert"]
                serial_number = req_cert["serial_number"].native  # int

                row = conn.execute(
                    "SELECT cert_pem, revoked FROM certificates WHERE serial = ?",
                    (hex(serial_number),),
                ).fetchone()

                if not row:
                    #raise ValueError(f"Certificate with serial {hex(serial_number)} not found")
                    # build an unsuccessful OCSP response and return it
                    ocsp_resp = OCSPResponseBuilder.build_unsuccessful(
                        OCSPResponseStatus.UNAUTHORIZED
                    )
                    return make_response(
                        ocsp_resp.public_bytes(serialization.Encoding.DER),
                        200,
                        {"Content-Type": "application/ocsp-response"},
                    )

                cert_pem, revoked_flag = row
                target_cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                revoked = (revoked_flag == 1)

                builder = builder.add_response(
                    cert=target_cert,
                    issuer=ca_cert,
                    algorithm=hashes.SHA1(),  # match client CertID hash if you later extract it
                    cert_status=OCSPCertStatus.REVOKED if revoked else OCSPCertStatus.GOOD,
                    this_update=now,
                    next_update=next_update,
                    revocation_time=now if revoked else None,
                    revocation_reason=x509.ReasonFlags.unspecified if revoked else None,
                )

        # 5) Responder ID
        builder = builder.responder_id(OCSPResponderEncoding.HASH, ca_cert)

        # 6) (Optional) copy nonce from request, if present
        req_exts = tbs_req["request_extensions"]
        if req_exts is not None:
            for ext in req_exts:
                if ext["extn_id"].native == "ocsp_nonce":
                    # ext["extn_value"].parsed gives you the raw nonce bytes
                    nonce_bytes = ext["extn_value"].native
                    builder = builder.add_extension(
                        x509.UnrecognizedExtension(
                            x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"),
                            nonce_bytes,
                        ),
                        critical=False,
                    )

        # 7) Sign once
        ocsp_response = builder.sign(private_key=private_key, algorithm=hashes.SHA256())

        return make_response(
            ocsp_response.public_bytes(serialization.Encoding.DER),
            200,
            {"Content-Type": "application/ocsp-response"},
        )

    except Exception as e:
        app.logger.error(f"OCSP request processing failed: {str(e)}")
        return f"OCSP request processing failed: {str(e)}", 400



# ---------- OCSPX Endpoint ----------



@app.route("/ocspX", methods=["POST", "GET"])
def ocspX():

    import datetime
    app.logger.debug("OCSP endpoint called.")
    try:
        # Load the OCSP request data
        request_data = request.data
        ocsp_request = load_der_ocsp_request(request_data)
        cert_serial = ocsp_request.serial_number

        # Retrieve the certificate details from your database
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            row = conn.execute("SELECT cert_pem, revoked FROM certificates WHERE serial = ?", (hex(cert_serial),)).fetchone()
            if not row:
                raise ValueError("Certificate not found")
            cert_pem, revoked_flag = row
            target_cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            revoked = (revoked_flag == 1)

        now = datetime.datetime.utcnow()
        next_update = now + datetime.timedelta(days=7)

        # Load the CA certificate to use as the issuer for OCSP responses
        with open(app.config["SUBCA_CERT_PATH"], "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Build the OCSP response using the CA certificate as issuer
        builder = OCSPResponseBuilder().add_response(
            cert=target_cert,
            issuer=ca_cert,  # Use the CA certificate as the issuer
            algorithm=hashes.SHA1(),
            cert_status=OCSPCertStatus.REVOKED if revoked else OCSPCertStatus.GOOD,
            this_update=now,
            next_update=next_update,
            revocation_time=now if revoked else None,
            revocation_reason=x509.ReasonFlags.unspecified if revoked else None
        )
        builder = builder.responder_id(OCSPResponderEncoding.HASH, ca_cert)

        # Load the CA private key to sign the OCSP response
        with open(app.config["SUBCA_KEY_PATH"], "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        ocsp_response = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
        
        return make_response(
            ocsp_response.public_bytes(serialization.Encoding.DER),
            200,
            {"Content-Type": "application/ocsp-response"}
        )
    except Exception as e:
        app.logger.error(f"OCSP request processing failed: {str(e)}")
        return f"OCSP request processing failed: {str(e)}", 400


# ---------- EST Endpoints ----------

@app.route("/.well-known/est/cacerts", methods=["GET"])
def est_cacerts():
    # 1) Generate a DER-encoded degenerate PKCS#7 containing the full chain
    #    into a temporary file.
    with tempfile.NamedTemporaryFile(suffix=".p7", delete=False) as tmp:
        p7_path = tmp.name

    subprocess.run([
        "openssl", "crl2pkcs7",
        "-nocrl",
        "-certfile", app.config["CHAIN_FILE_PATH"],     # full chain PEM
        "-outform", "DER",
        "-out", p7_path
    ], check=True)

    # 2) Read and Base64-encode it
    der = open(p7_path, "rb").read()
    b64 = base64.encodebytes(der).decode("ascii")

    # 3) Return as S/MIME with the required headers
    headers = {
        "Content-Type": "application/pkcs7-mime; smime-type=certs",
        "Content-Transfer-Encoding": "base64",
        "Content-Disposition": 'attachment; filename="cacerts.p7"'
    }
    return Response(b64, headers=headers, status=200)



def normalize_to_der(raw: bytes) -> bytes:
    # 1) PEM-wrapped CSR? Strip headers & decode.
    if raw.strip().startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
        text = raw.decode("ascii")
        b64 = "".join(
            line for line in text.splitlines()
            if not line.startswith("-----")
        )
        return base64.b64decode(b64)

    # 2) Bare base64 (no headers) — try to decode if it's all base64 chars.
    try:
        s = raw.decode("ascii")
        if re.fullmatch(r"[A-Za-z0-9+/=\s]+", s):
            return base64.b64decode(s)
    except (UnicodeDecodeError, binascii.Error):
        pass

    # 3) Otherwise assume it’s already DER
    return raw



@app.route("/.well-known/est/simpleenroll", methods=["POST"])
def est_enroll():
    raw = request.get_data()
    ext_block = request.form.get("ext_block", "v3_ext")

    # 1) Normalize CSR to DER
    try:
        der_csr = normalize_to_der(raw)
    except binascii.Error:
        return "Invalid CSR encoding", 400

    # 2) Write CSR DER to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csr") as csr_file:
        csr_file.write(der_csr)
        csr_der_filename = csr_file.name

    # 3) Prepare temp file for the issued cert
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
        cert_filename = cert_file.name

    # 4) Generate serial & read validity
    custom_serial_str = hex(secrets.randbits(64))
    try:
        with open(app.config["VALIDITY_CONF"], "r") as f:
            validity_days = f.read().strip()
    except FileNotFoundError:
        validity_days = "365"

    # 5) Sign CSR with OpenSSL
    cmd = [
        "openssl", "x509", "-req",
        "-inform", "DER",
        "-in", csr_der_filename,
        "-CA", app.config["SUBCA_CERT_PATH"],
        "-CAkey", app.config["SUBCA_KEY_PATH"],
        "-set_serial", custom_serial_str,
        "-days", validity_days,
        "-out", cert_filename,
        "-extfile", app.config["SERVER_EXT_PATH"],
        "-extensions", ext_block
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)

    # 6) Read the issued cert (PEM)
    with open(cert_filename, "r") as f:
        cert_pem = f.read()

    # 7) Record in the database
    cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    # 5) Sign CSR with OpenSSL
    cmd = [
        "openssl", "x509", "-req",
        "-inform", "DER",
        "-in", csr_der_filename,
        "-CA", app.config["SUBCA_CERT_PATH"],
        "-CAkey", app.config["SUBCA_KEY_PATH"],
        "-set_serial", custom_serial_str,
        "-days", validity_days,
        "-out", cert_filename,
        "-extfile", app.config["SERVER_EXT_PATH"],
        "-extensions", ext_block
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)

    # 6) Read the issued cert (PEM)
    with open(cert_filename, "r") as f:
        cert_pem = f.read()

    # 7) Record in the database
    cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    subject_str = ", ".join(f"{attr.oid._name}={attr.value}" for attr in cert_obj.subject)
    actual_serial = hex(cert_obj.serial_number)
    from flask_login import current_user
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute(
            "INSERT INTO certificates (subject, serial, cert_pem, user_id) VALUES (?, ?, ?, ?)",
            (subject_str, actual_serial, cert_pem, current_user.id)
        )

    # 8) Write the signed cert to a file (for pkcs7 conversion)
    with open("est_signed_cert.pem", "wb") as f:
        f.write(cert_pem.encode())

    # 9) Build a PKCS#7 container **with only the issued certificate** (no chain)
    subprocess.run([
        "openssl", "crl2pkcs7",
        "-nocrl",
        "-certfile", "est_signed_cert.pem",
        "-outform", "DER",
        "-out", "est_cert_chain.p7"
    ], check=True)

    # 10) Read, base64-encode, and return via make_response
    pkcs7_der = open("est_cert_chain.p7", "rb").read()
    b64 = base64.encodebytes(pkcs7_der)
    resp = make_response(b64, 200)
    resp.headers["Content-Type"]              = "application/pkcs7-mime; smime-type=signed-data"
    resp.headers["Content-Transfer-Encoding"] = "base64"
    resp.headers["Content-Disposition"]       = 'attachment; filename="enroll.p7"'
    return resp



# ---------- PFX Helpers ----------


def find_key_for_certificate(cert_pem: str):
    """
    Try to find a Key row whose public key matches this certificate's public key,
    using OpenSSL CLI. Returns a Key object or None.
    """
    # Write cert to temp file
    with tempfile.NamedTemporaryFile("w+", suffix=".pem", delete=False) as cert_f:
        cert_f.write(cert_pem)
        cert_f.flush()
        cert_path = cert_f.name

    try:
        # Extract public key from certificate
        proc = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-pubkey", "-noout"],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            app.logger.error(f"Failed to extract pubkey from cert: {proc.stderr}")
            return None
        cert_pubkey_pem = proc.stdout.strip()
    finally:
        try:
            os.remove(cert_path)
        except OSError:
            pass

    # Compare with each stored key's public key
    for key_obj in Key.query.all():
        with tempfile.NamedTemporaryFile("w+", suffix=".pem", delete=False) as key_f:
            key_f.write(key_obj.private_key)
            key_f.flush()
            key_path = key_f.name

        try:
            pub_proc = subprocess.run(
                ["openssl", "pkey", "-in", key_path, "-pubout"],
                capture_output=True,
                text=True,
            )
            if pub_proc.returncode != 0:
                app.logger.warning(f"Failed to extract pubkey for key {key_obj.id}: {pub_proc.stderr}")
                continue

            key_pub_pem = pub_proc.stdout.strip()
            if key_pub_pem == cert_pubkey_pem:
                app.logger.info(f"Matched certificate to key id={key_obj.id}")
                return key_obj

        finally:
            try:
                os.remove(key_path)
            except OSError:
                pass

    app.logger.warning("No matching key found for certificate")
    return None




def build_pfx_openssl(cert_pem: str, key_pem: str, chain_path: str, password: str) -> bytes:
    """
    Build a PKCS#12 (.pfx) file using OpenSSL CLI:
      -inkey: user private key
      -in:   user certificate
      -certfile: CA chain (if provided)
    """
    cert_file = tempfile.NamedTemporaryFile("w+", suffix=".pem", delete=False)
    key_file  = tempfile.NamedTemporaryFile("w+", suffix=".pem", delete=False)
    pfx_file  = tempfile.NamedTemporaryFile("wb", suffix=".pfx", delete=False)

    cert_path = cert_file.name
    key_path  = key_file.name
    pfx_path  = pfx_file.name

    cert_file.write(cert_pem)
    cert_file.flush()
    key_file.write(key_pem)
    key_file.flush()
    cert_file.close()
    key_file.close()
    pfx_file.close()

    cmd = [
        "openssl", "pkcs12", "-export",
        "-inkey", key_path,
        "-in", cert_path,
        "-out", pfx_path,
        "-passout", f"pass:{password}",
    ]

    if chain_path and os.path.exists(chain_path):
        cmd.extend(["-certfile", chain_path])

    app.logger.debug("Running PFX command: %s", " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"OpenSSL pkcs12 failed: {proc.stderr}")

        with open(pfx_path, "rb") as f:
            pfx_bytes = f.read()
        return pfx_bytes
    finally:
        for p in (cert_path, key_path, pfx_path):
            try:
                os.remove(p)
            except OSError:
                pass


@app.route("/downloads/pfx/<int:cert_id>", methods=["POST"])
def download_pfx(cert_id):
    password = request.form.get("pfx_password", "").strip()
    if not password:
        flash("PFX password is required.", "error")
        return redirect("/certs")

    # 1) Fetch cert from DB
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        row = conn.execute(
            "SELECT cert_pem FROM certificates WHERE id = ?",
            (cert_id,)
        ).fetchone()

    if not row:
        flash("Certificate not found.", "error")
        return redirect("/certs")

    cert_pem = row[0]

    # 2) Find matching key
    key_obj = find_key_for_certificate(cert_pem)
    if not key_obj:
        flash("Could not find matching private key for this certificate.", "error")
        return redirect("/certs")

    # 3) Build PFX via OpenSSL
    try:
        chain_path = app.config.get("SUBCA_CERT_PATH")
        pfx_bytes = build_pfx_openssl(
            cert_pem=cert_pem,
            key_pem=key_obj.private_key,
            chain_path=chain_path,
            password=password,
        )
    except Exception as e:
        app.logger.error(f"Failed to build PFX for cert {cert_id}: {e}")
        flash("Failed to build PFX file.", "error")
        return redirect("/certs")

    # 4) Derive CN-based filename (same logic as PEM download)
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        common_name = None
        for attribute in cert.subject:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                common_name = attribute.value
                break
        filename = f"{common_name.replace(' ', '')}.pfx" if common_name else f"cert_{cert_id}.pfx"
    except Exception:
        filename = f"cert_{cert_id}.pfx"

    buf = io.BytesIO(pfx_bytes)
    buf.seek(0)
    return send_file(
        buf,
        as_attachment=True,
        download_name=filename,
        mimetype="application/x-pkcs12",
    )


# --- Change Password ---
@app.route("/account", methods=["GET"])
@login_required
def account():
    return render_template("account.html")

@app.route("/change_password", methods=["POST"])
@login_required
def change_password():
    current_password = request.form.get("current_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()
    if not current_user.check_password(current_password):
        flash("Current password is incorrect.", "error")
        return redirect(url_for('account'))
    if not new_password or new_password != confirm_password:
        flash("New passwords do not match or are empty.", "error")
        return redirect(url_for('account'))
    from werkzeug.security import generate_password_hash
    import sqlite3
    db_path = app.config["DB_PATH"]
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), current_user.id))
    con.commit()
    con.close()
    flash("Password changed successfully.", "success")
    app.logger.info(f"User {current_user.username} changed their password.")
    return redirect(url_for('account'))



# ---------- Run Servers ----------
from werkzeug.serving import run_simple

def run_http_scep_only():
    http_app = Flask("http_scep")

    http_app.config.update(app.config)

    # --- attach the same logger handlers & level as your main 'app' ---
    http_app.logger.handlers.clear()
    for h in app.logger.handlers:
      http_app.logger.addHandler(h)
    http_app.logger.setLevel(app.logger.level)
    # --- end logging patch ---

    http_app.register_blueprint(scep_app)

    run_simple("0.0.0.0", HTTP_SCEP_PORT, http_app, use_reloader=False, use_debugger=True)

from threading import Thread
from http.server import HTTPServer, SimpleHTTPRequestHandler


def run_http_general():
    app.run(host="0.0.0.0", port=HTTP_DEFAULT_PORT,use_reloader=False, use_debugger=True)

def run_https():
    app.run(host="0.0.0.0", port=HTTPS_PORT, ssl_context=(SSL_CERT_PATH, SSL_KEY_PATH), use_reloader=False, use_debugger=True)

def run_trusted_https():
    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=TRUSTED_SSL_CERT_PATH, keyfile=TRUSTED_SSL_KEY_PATH)
    context.load_verify_locations(cafile=app.config["CHAIN_FILE_PATH"])
    context.verify_mode = ssl.CERT_REQUIRED  # Force client cert verification
    app.run(host="0.0.0.0", port=TRUSTED_HTTPS_PORT, ssl_context=context, use_reloader=False, use_debugger=True)




if __name__ == "__main__":
    # Initialize CRL on startup (creates empty CRL if no revoked certificates)
    try:
        update_crl()
        app.logger.info("CRL initialized successfully")
    except Exception as e:
        app.logger.warning(f"Failed to initialize CRL on startup: {e}")
    
    Thread(target=run_https).start()
    Thread(target=run_trusted_https).start()
    Thread(target=run_http_scep_only).start()
    Thread(target=run_http_general, daemon=True).start()



