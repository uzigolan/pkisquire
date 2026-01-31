# Debug route for test: returns current_user info
from flask_login import current_user
import os
import sqlite3
import json
import logging
import subprocess
import tempfile
import io
import zipfile
import configparser
import shutil
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
from flask import Flask, render_template, request, redirect, send_file, make_response, flash, url_for, Response, session, abort, jsonify, current_app
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from users import users_bp, register_login_signals, init_users_config, verify_api_token
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
import inspect_logic
from asn1crypto import x509 as asn1_x509

from ldap_utils import ldap_authenticate, ldap_user_exists
from user_models import User, get_user_by_id, get_user_theme_style, set_user_theme_style, get_user_theme_color, set_user_theme_color
# Load shared extensions and blueprints
from extensions import db           # Shared SQLAlchemy instance
from x509_profiles import x509_profiles_bp, Profile, X509_PROFILE_DIR
from x509_keys import x509_keys_bp, Key
from x509_requests import x509_requests_bp
from scep import scep_app
from openssl_utils import get_provider_args
from ra_policies import RAPolicyManager, DEFAULT_VALIDITY_DAYS

#from flask import render_template, current_app as app
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# --- User Registration, Login, Logout Routes ---
from user_models import get_user_by_username, create_user_db, update_last_login


# --- Manage Users (Admin Only) ---
## User management helpers moved to users.py blueprint


# --- API endpoint for AJAX login status polling ---
from flask import jsonify



# --- Server-side session tracking for all logged-in users ---

## ensure_sessions_table moved to users.py if needed






app = Flask(__name__, template_folder="html_templates")
import logging
app.logger.info(f"[STARTUP] app.config['DB_PATH'] = {app.config.get('DB_PATH')}")
register_login_signals(app)
app.register_blueprint(users_bp)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True
# Clear template cache on each load to avoid stale HTML in dev
app.jinja_env.cache = {}



## get_logged_in_user_ids moved to users.py


## get_user_idle_map moved to users.py

# Track logged-in users by user_id in a set
import threading
LOGGED_IN_USERS = set()
LOGGED_IN_USERS_LOCK = threading.Lock()
LDAP_IMPORTED_USERS = set()  # runtime memory of users created via LDAP
LDAP_SOURCE_CACHE = {}  # username -> 'ldap'|'local' for this runtime


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


## get_auth_source_for_username moved to users.py
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
app.config["allow_self_registration"] = _cfg.get("DEFAULT", "allow_self_registration", fallback="true")
init_users_config(app, _cfg)

ca_mode = _cfg.get("CA", "mode", fallback="EC").upper()
if ca_mode not in ("EC", "RSA"):
    ca_mode = "EC"

app.config["SUBCA_KEY_PATH"]   = _cfg.get("CA", f"SUBCA_KEY_PATH_{ca_mode}")
app.config["SUBCA_CERT_PATH"]  = _cfg.get("CA", f"SUBCA_CERT_PATH_{ca_mode}")
app.config["CHAIN_FILE_PATH"]  = _cfg.get("CA", f"CHAIN_FILE_PATH_{ca_mode}")
app.config["ROOT_CERT_PATH"]   = _cfg.get("CA", "ROOT_CERT_PATH")
app.config["CA_MODE"]          = ca_mode
print(f"CA_MODE set to: {ca_mode}")
app.config["LDAP_HOST"]           = _cfg.get("LDAP", "LDAP_HOST", fallback=None)
app.config["LDAP_PORT"]           = _cfg.getint("LDAP", "LDAP_PORT", fallback=389)
app.config["LDAP_BASE_DN"]        = _cfg.get("LDAP", "BASE_DN", fallback=None)
app.config["LDAP_PEOPLE_DN"]      = _cfg.get("LDAP", "PEOPLE_DN", fallback=None)
app.config["LDAP_ADMIN_DN"]       = _cfg.get("LDAP", "ADMIN_DN", fallback=None)
app.config["LDAP_ADMIN_PASSWORD"] = _cfg.get("LDAP", "ADMIN_PASSWORD", fallback=None)
app.config["LDAP_ENABLED"]        = _cfg.getboolean("LDAP", "enabled", fallback=bool(_cfg.get("LDAP", "LDAP_HOST", fallback=None)))

# —— VAULT section —— 
from config_storage import load_vault_config

VAULT_CONFIG = load_vault_config(CONFIG_PATH)
app.config["VAULT_ENABLED"] = VAULT_CONFIG.get('enabled', False)
app.config["VAULT_CONFIG"] = VAULT_CONFIG

# Global Vault client (will be initialized later if enabled)
vault_client = None

# —— SCEP section —— 
app.config["SCEP_ENABLED"]   = _cfg.getboolean("SCEP", "enabled", fallback=True)
app.config["SCEP_SERIAL_PATH"] = _cfg.get("SCEP", "serial_file", fallback=None)
app.config["SCEPY_DUMP_DIR"]   = _cfg.get("SCEP", "dump_dir", fallback=None)
app.config["SCEP_CHALLENGE_PASSWORD_ENABLED"] = _cfg.getboolean("SCEP", "challenge_password_enabled", fallback=False)
app.config["SCEP_CHALLENGE_PASSWORD_VALIDITY"] = _cfg.get("SCEP", "challenge_password_validity", fallback="60m")
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

def get_ra_policy_manager() -> RAPolicyManager:
    # Lazily initialize and reuse a single manager instance
    mgr = getattr(app, "_ra_policy_mgr", None)
    if mgr is None:
        mgr = RAPolicyManager(app.config["DB_PATH"], app.logger)
        app._ra_policy_mgr = mgr
    return mgr

def _resolve_ra_policy(policy_id_str=None, user_id=None):
    """
    Return (manager, policy) choosing the given policy_id when provided,
    otherwise falling back to the default policy for the user/system.
    """
    mgr = get_ra_policy_manager()
    # Admins can load any policy; skip user scoping
    if hasattr(current_user, "is_admin") and current_user.is_admin():
        user_id = None
    policy = None
    if policy_id_str:
        try:
            policy_id = int(policy_id_str)
            policy = mgr.get_policy(policy_id=policy_id, user_id=user_id)
        except (TypeError, ValueError):
            policy = None
    if not policy:
        policy = mgr.get_default_policy(user_id=user_id)
    return mgr, policy



# Flask and SQLAlchemy configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + app.config["DB_PATH"]
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "marketing"  # Replace with a secure unique secret in production

db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'users.login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(int(user_id))

@app.context_processor
def inject_theme_style():
    theme_style = "classic"
    theme_color = "snow"
    if current_user.is_authenticated:
        try:
            theme_style = get_user_theme_style(current_user.id)
            theme_color = get_user_theme_color(current_user.id)
        except Exception:
            theme_style = "modern"
            theme_color = "snow"
    return {"theme_style": theme_style, "theme_color": theme_color}

# ---------- Logging Setup ----------
from logging import Formatter
from logging.handlers import RotatingFileHandler

# Add custom TRACE logging level
TRACE = 5
logging.addLevelName(TRACE, "TRACE")

def trace(self, message, *args, **kwargs):
    # Only log TRACE messages if logger level is set to TRACE or lower
    # Use isEnabledFor which properly checks if this level would be logged
    if self.isEnabledFor(5):  # 5 = TRACE level
        self._log(5, message, args, **kwargs)

logging.Logger.trace = trace

# Read logging configuration from config.ini (needs to be after _cfg is loaded)
# Note: _cfg is loaded at line ~243, basedir at line ~239
log_level_str = _cfg.get("LOGGING", "log_level", fallback="DEBUG").upper()
log_file_path = _cfg.get("LOGGING", "log_file", fallback="logs/server.log")

# Map level name to logging constant
level_map = {
    "TRACE": TRACE,
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL
}
log_level = level_map.get(log_level_str, logging.DEBUG)

# Put logs in configured location (create dir if needed)
LOG_FILE = os.path.join(basedir, log_file_path)
LOG_DIR = os.path.dirname(LOG_FILE)
os.makedirs(LOG_DIR, exist_ok=True)
app.config["LOG_FILE"] = LOG_FILE  # expose to routes

# One rotating file handler (no stdout handler to avoid confusion)
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
file_handler.setLevel(TRACE)  # Allow all levels including TRACE
formatter = Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
file_handler.setFormatter(formatter)

# Apply to Flask app logger
app.logger.handlers.clear()
app.logger.setLevel(log_level)
app.logger.addHandler(file_handler)
app.logger.propagate = False

# Configure root logger to capture all module loggers (ca, vault_client, etc.)
root_logger = logging.getLogger()
root_logger.handlers.clear()
root_logger.setLevel(log_level)
root_logger.addHandler(file_handler)

# Also capture Werkzeug (request logs) into the same file
# Add filter to exclude noisy requests and strip ANSI color codes
import re

class ExcludeNoisyRequestsFilter(logging.Filter):
    # ANSI color code pattern
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    
    def filter(self, record):
        # Get the full formatted message
        msg = record.getMessage()
        # Filter out noisy requests entirely
        noisy_requests = (
            '/logs/last',
            '/static/favicon',
            'GET /users/tokens/state',
            'GET /users/events/api',
        )
        if any(segment in msg for segment in noisy_requests):
            return False
        # Strip ANSI color codes from the formatted message
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = self.ansi_escape.sub('', record.msg)
        return True

werkzeug_logger = logging.getLogger("werkzeug")
werkzeug_logger.handlers.clear()
werkzeug_logger.setLevel(logging.INFO)  # Set back to INFO for other requests
werkzeug_logger.addFilter(ExcludeNoisyRequestsFilter())
werkzeug_logger.addHandler(file_handler)
werkzeug_logger.propagate = False

app.logger.info("Logging initialized. Writing to %s (level=%s)", LOG_FILE, logging.getLevelName(log_level))


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
# Register events blueprint
from events import bp as events_bp
app.register_blueprint(x509_profiles_bp)
app.register_blueprint(x509_keys_bp)
app.register_blueprint(x509_requests_bp)
app.register_blueprint(events_bp)
if app.config["SCEP_ENABLED"]:
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

from flask import g
# ---------- Main Routes ----------
# Ensure g.user_role and g.user_id are set for all requests
@app.before_request
def set_user_context():
    if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
        g.user_id = current_user.id
        g.user_role = current_user.role if hasattr(current_user, 'role') else 'user'
    else:
        g.user_id = None
        g.user_role = 'user'
@app.context_processor
def inject_ca_mode():
    # so every template gets a 'ca_mode' variable
    ca_mode_value = app.config.get("CA_MODE", "UNKNOWN")
    app.logger.debug(f"inject_ca_mode called: returning ca_mode={ca_mode_value}")
    return {"ca_mode": ca_mode_value}


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


# Debug route for test: returns current_user info
@app.route('/debug_current_user')
def debug_current_user():
    from flask_login import current_user
    if current_user.is_authenticated:
        return {
            'authenticated': True,
            'username': current_user.username,
            'role': getattr(current_user, 'role', None),
            'is_admin': current_user.is_admin() if hasattr(current_user, 'is_admin') else False
        }
    else:
        return {'authenticated': False}


# --- Individual Challenge Password Deletion Route ---
@app.route('/delete_challenge_password', methods=['POST'])
@login_required
def delete_challenge_password():
    value = request.form.get('value') or request.args.get('value')
    if not value:
        flash('No challenge password specified.', 'error')
        return redirect(url_for('challenge_passwords'))
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT user_id, consumed, created_at, validity FROM challenge_passwords WHERE value = ?",
            (value,),
        ).fetchone()
        if not row:
            flash('Challenge password not found.', 'error')
            return redirect(url_for('challenge_passwords'))
        if not current_user.is_admin() and row['user_id'] != current_user.id:
            flash('You do not have permission to delete this challenge password.', 'error')
            return redirect(url_for('challenge_passwords'))
        if row['consumed']:
            flash('Consumed challenge passwords cannot be deleted.', 'error')
            return redirect(url_for('challenge_passwords'))
        conn.execute("DELETE FROM challenge_passwords WHERE value = ?", (value,))
        conn.commit()
        # Event logging
        try:
            from events import log_event
            log_event(
                event_type="delete",
                resource_type="challenge_password",
                resource_name=value,
                user_id=current_user.id,
                details={}
            )
        except Exception:
            pass
    flash('Challenge password deleted.', 'success')
    return redirect(url_for('challenge_passwords'))



@app.route('/delete_all_expired_challenge_passwords', methods=['POST'])
@login_required
def delete_all_expired_challenge_passwords():
    from datetime import datetime, timedelta
    now = datetime.utcnow()
    scope = request.form.get('scope') or request.args.get('scope', 'own')
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        if current_user.is_admin() and scope == 'all':
            rows = conn.execute("SELECT value, created_at, validity, consumed FROM challenge_passwords").fetchall()
        else:
            rows = conn.execute("SELECT value, created_at, validity, consumed, user_id FROM challenge_passwords WHERE user_id = ?", (current_user.id,)).fetchall()
        to_delete = []
        for row in rows:
            if row['consumed']:
                continue
            expires_at = ''
            if row['created_at'] and row['validity']:
                m = re.match(r'^(\d+)([mhd])$', row['validity'])
                if m:
                    num, unit = int(m.group(1)), m.group(2)
                    if unit == 'm':
                        delta = timedelta(minutes=num)
                    elif unit == 'h':
                        delta = timedelta(hours=num)
                    elif unit == 'd':
                        delta = timedelta(days=num)
                    else:
                        delta = timedelta(minutes=60)
                    try:
                        created_dt = datetime.strptime(row['created_at'], '%Y-%m-%d %H:%M:%S UTC')
                        expires_dt = created_dt + delta
                        if now > expires_dt:
                            to_delete.append(row['value'])
                    except Exception:
                        continue
        if to_delete:
            conn.executemany("DELETE FROM challenge_passwords WHERE value = ?", [(v,) for v in to_delete])
            conn.commit()
            # Event logging
            try:
                from events import log_event
                log_event(
                    event_type="bulk_delete",
                    resource_type="challenge_password",
                    resource_name="bulk",
                    user_id=current_user.id,
                    details={"count": len(to_delete)}
                )
            except Exception:
                pass
            flash(f"Deleted {len(to_delete)} expired challenge passwords.", "success")
        else:
            flash("No expired challenge passwords to delete.", "info")
    return redirect(url_for('challenge_passwords'))



# --- Challenge Passwords AJAX Data Route ---
@app.route('/challenge_passwords/data', methods=['GET'])
@login_required
def challenge_passwords_data():
    # Return the current challenge password list as JSON from DB
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        if current_user.is_admin():
            rows = conn.execute(
                "SELECT value, user_id, created_at, validity, consumed FROM challenge_passwords ORDER BY created_at DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT value, user_id, created_at, validity, consumed FROM challenge_passwords WHERE user_id = ? ORDER BY created_at DESC",
                (current_user.id,),
            ).fetchall()
    from user_models import get_username_by_id
    result = []
    for row in rows:
        expires_at_utc = ""
        expires_at_local = ""
        expired_flag = False
        allow_delete = not bool(row["consumed"])
        if row["created_at"] and row["validity"]:
            m = re.match(r"^(\d+)([mhd])$", row["validity"])
            if m:
                num, unit = int(m.group(1)), m.group(2)
                if unit == "m":
                    delta = timedelta(minutes=num)
                elif unit == "h":
                    delta = timedelta(hours=num)
                elif unit == "d":
                    delta = timedelta(days=num)
                else:
                    delta = timedelta(minutes=60)
                try:
                    created_dt = datetime.strptime(row["created_at"], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
                    expires_dt = created_dt + delta
                    expires_at_utc = expires_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                    expires_at_local = expires_dt.astimezone().strftime("%Y-%m-%d %H:%M")
                    expired_flag = datetime.now(timezone.utc) > expires_dt
                except Exception:
                    pass
        result.append({
            'value': row['value'],
            'user': get_username_by_id(row['user_id']) if row['user_id'] else '',
            'created_at_utc': row['created_at'],
            'created_at_local': (
                datetime.strptime(row['created_at'], '%Y-%m-%d %H:%M:%S UTC')
                .replace(tzinfo=timezone.utc)
                .astimezone()
                .strftime('%Y-%m-%d %H:%M')
            ) if row['created_at'] else '',
            'validity': row['validity'],
            'expires_at_utc': expires_at_utc,
            'expires_at_local': expires_at_local,
            'expired': expired_flag,
            'consumed': bool(row['consumed']),
            'allow_delete': allow_delete
        })
    return jsonify(result)

def _parse_validity_timedelta(validity_str):
    import re, datetime
    m = re.match(r"^(\d+)([mhd])$", (validity_str or "").strip())
    if not m:
        return datetime.timedelta(minutes=60), "60m"
    num, unit = int(m.group(1)), m.group(2)
    if unit == 'm':
        return datetime.timedelta(minutes=num), validity_str
    if unit == 'h':
        return datetime.timedelta(hours=num), validity_str
    if unit == 'd':
        return datetime.timedelta(days=num), validity_str
    return datetime.timedelta(minutes=60), "60m"

@app.route("/api/challenge_passwords", methods=["POST"])
def api_create_challenge_password():
    """
    Create a new challenge password using an API token.
    Auth: Authorization: Bearer <token> (or token param/header).
    """
    raw_token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        raw_token = auth_header.split(" ", 1)[1].strip()
    raw_token = raw_token or request.headers.get("X-API-Token") or request.args.get("token") or (request.json.get("token") if request.is_json else None)
    if not raw_token:
        return jsonify({"error": "API token required"}), 401
    token_info = verify_api_token(raw_token)
    if not token_info:
        return jsonify({"error": "Invalid or expired API token"}), 401
    if not app.config.get('SCEP_CHALLENGE_PASSWORD_ENABLED', False):
        return jsonify({"error": "Challenge password feature is disabled"}), 400

    validity_str = app.config.get('SCEP_CHALLENGE_PASSWORD_VALIDITY', '60m').strip()
    delta, validity_str = _parse_validity_timedelta(validity_str)

    import secrets, datetime
    now = datetime.datetime.now(datetime.UTC)
    value = secrets.token_bytes(16).hex().upper()
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute(
            "INSERT INTO challenge_passwords (value, user_id, created_at, validity, consumed) VALUES (?, ?, ?, ?, 0)",
            (value, token_info["user_id"], now.strftime('%Y-%m-%d %H:%M:%S UTC'), validity_str,)
        )
        conn.commit()
    expires_at = (now + delta).strftime('%Y-%m-%d %H:%M:%S UTC')
    try:
        from events import log_event
        log_event(
            event_type="create",
            resource_type="challenge_password",
            resource_name=value,
            user_id=token_info["user_id"],
            details={"validity": validity_str, "via": "api_token"}
        )
    except Exception:
        pass
    return jsonify({
        "value": value,
        "user_id": token_info["user_id"],
        "validity": validity_str,
        "created_at": now.strftime('%Y-%m-%d %H:%M:%S UTC'),
        "expires_at": expires_at
    }), 201

# --- Challenge Password Management UI ---
@app.route('/challenge_passwords', methods=['GET', 'POST'])
@login_required
def challenge_passwords():
    import secrets, datetime
    validity_str = app.config.get('SCEP_CHALLENGE_PASSWORD_VALIDITY', '60m')
    # Parse validity string (e.g., 60m, 2h, 1d)
    import re
    m = re.match(r'^(\d+)([mhd])$', validity_str)
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
    from flask import redirect, url_for, session
    generated = None
    if request.method == 'POST':
        now = datetime.datetime.now(datetime.UTC)
        value = secrets.token_bytes(16).hex().upper()
        validity = validity_str
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            conn.execute(
                "INSERT INTO challenge_passwords (value, user_id, created_at, validity, consumed) VALUES (?, ?, ?, ?, 0)",
                (value, current_user.id, now.strftime('%Y-%m-%d %H:%M:%S UTC'), validity,)
            )
            conn.commit()
        # Event logging
        try:
            from events import log_event
            log_event(
                event_type="create",
                resource_type="challenge_password",
                resource_name=value,
                user_id=current_user.id,
                details={"validity": validity}
            )
        except Exception:
            pass
        session['generated_challenge_password'] = {
            'value': value,
            'user': current_user.username,
            'created_at': now.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'validity': validity,
            'consumed': False
        }
        return redirect(url_for('challenge_passwords'))
    generated = session.pop('generated_challenge_password', None)
    # Fetch challenge passwords from DB (admin: all, user: own only)
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        if current_user.is_admin():
            rows = conn.execute("SELECT value, user_id, created_at, validity, consumed FROM challenge_passwords ORDER BY created_at DESC").fetchall()
        else:
            rows = conn.execute("SELECT value, user_id, created_at, validity, consumed FROM challenge_passwords WHERE user_id = ? ORDER BY created_at DESC", (current_user.id,)).fetchall()
    from user_models import get_username_by_id
    challenge_passwords = []
    for row in rows:
        # Calculate expires_at
        import re, datetime
        expires_at = ''
        expires_at_local = ''
        if row['created_at'] and row['validity']:
            m = re.match(r'^(\d+)([mhd])$', row['validity'])
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
                try:
                    created_dt = datetime.datetime.strptime(row['created_at'], '%Y-%m-%d %H:%M:%S UTC').replace(tzinfo=datetime.timezone.utc)
                    expires_dt = created_dt + delta
                    expires_at = expires_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                    expires_at_local = expires_dt.astimezone().strftime('%Y-%m-%d %H:%M')
                except Exception:
                    expires_at = ''
        # Determine expired status
        expired = False
        allow_delete = not bool(row['consumed'])
        if expires_at and not bool(row['consumed']):
            try:
                expires_dt = datetime.datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S UTC').replace(tzinfo=datetime.timezone.utc)
                if datetime.datetime.now(datetime.timezone.utc) > expires_dt:
                    expired = True
            except Exception:
                pass
        challenge_passwords.append({
            'value': row['value'],
            'user': get_username_by_id(row['user_id']) if row['user_id'] else '',
            'created_at_utc': row['created_at'],
            'created_at_local': (
                datetime.datetime.strptime(row['created_at'], '%Y-%m-%d %H:%M:%S UTC')
                .replace(tzinfo=datetime.timezone.utc)
                .astimezone()
                .strftime('%Y-%m-%d %H:%M')
            ) if row['created_at'] else '',
            'validity': row['validity'],
            'expires_at_utc': expires_at,
            'expires_at_local': expires_at_local,
            'consumed': bool(row['consumed']),
            'expired': expired,
            'allow_delete': allow_delete
        })
    return render_template('challenge_passwords.html',
        generated=generated,
        challenge_passwords=challenge_passwords,
        is_admin=current_user.is_admin())









# AJAX endpoint to serve server extension config content
@app.route('/get_server_ext_content')
@login_required
def get_server_ext_content():
    policy_id = request.args.get('policy_id')
    name = request.args.get('name')
    mgr, policy = _resolve_ra_policy(policy_id, current_user.id)
    if not policy and name:
        policy = mgr.get_policy(name=name, user_id=current_user.id)
    if not policy:
        return 'Policy not found', 404
    content = policy.get("ext_config") or "[ v3_ext ]\n# No additional extensions"
    return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}



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




@app.route("/certs")
@login_required
def index():
    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            cur = conn.cursor()
            if current_user.is_admin():
                cur.execute("""
                    SELECT c.id, c.subject, c.serial, c.revoked, c.cert_pem, c.user_id, c.issued_via
                    FROM certificates c
                    ORDER BY c.id DESC
                """)
            else:
                cur.execute("""
                    SELECT c.id, c.subject, c.serial, c.revoked, c.cert_pem, c.user_id, c.issued_via
                    FROM certificates c
                    WHERE c.user_id = ?
                    ORDER BY c.id DESC
                """, (current_user.id,))
            rows = cur.fetchall()
        #app.logger.debug(f"DB retruned {len(rows)} certificates for user {current_user.username}    (id={current_user.id})")
        certs = []
        now = datetime.now(timezone.utc)
        from user_models import get_user_by_id
        for row in rows:
            # Now expecting 7 columns: id, subject, serial, revoked, cert_pem, user_id, issued_via
            id_, subject, serial, revoked, cert_pem, user_id, issued_via = row
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
            app.logger.trace(f"Cert ID {id_}: keycol={keycol}, expired={expired}   revoked={revoked}")
            certs.append((id_, subject, serial, keycol, issue_date, revoked, expired, username, issued_via, cert_pem))

        return render_template(
            "list_certificates.html",
            certs=certs,
            is_admin=current_user.is_admin()
        )
    except Exception as e:
        app.logger.error(f"Failed to load index: {e}")
        return f"Error: {e}", 500


@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            cur = conn.cursor()
            if current_user.is_admin():
                cur.execute("""
                    SELECT c.cert_pem, c.revoked, c.issued_via
                    FROM certificates c
                    ORDER BY c.id DESC
                """)
            else:
                cur.execute("""
                    SELECT c.cert_pem, c.revoked, c.issued_via
                    FROM certificates c
                    WHERE c.user_id = ?
                    ORDER BY c.id DESC
                """, (current_user.id,))
            rows = cur.fetchall()

        now = datetime.now(timezone.utc)
        summary = {
            "total": 0,
            "valid": 0,
            "expired": 0,
            "revoked": 0,
        }
        enrollment = {
            "ui": 0,
            "est": 0,
            "scep": 0,
        }

        for cert_pem, revoked, issued_via in rows:
            summary["total"] += 1
            if revoked:
                summary["revoked"] += 1
            else:
                try:
                    cert = x509.load_pem_x509_certificate(
                        cert_pem.encode(), default_backend()
                    )
                    expired = cert.not_valid_after_utc < now
                except Exception:
                    expired = False
                if expired:
                    summary["expired"] += 1
                else:
                    summary["valid"] += 1

            via = (issued_via or "unknown").lower()
            if via == "ui":
                enrollment["ui"] += 1
            elif via == "est":
                enrollment["est"] += 1
            elif via == "scep":
                enrollment["scep"] += 1

        return render_template(
            "dashboard.html",
            summary=summary,
            enrollment=enrollment,
            is_admin=current_user.is_admin(),
        )
    except Exception as e:
        app.logger.error(f"Failed to load dashboard: {e}")
        return f"Error: {e}", 500


@app.route("/dashboard/activity_data", methods=["GET"])
@login_required
def dashboard_activity_data():
    try:
        limit = int(request.args.get("limit", 2000))
        limit = max(100, min(limit, 10000))
        start_ts = request.args.get("start")
        end_ts = request.args.get("end")
        user_role = getattr(g, "user_role", "user")
        user_id = getattr(g, "user_id", None)

        query = "SELECT event_type, resource_type, resource_name, timestamp, details FROM events WHERE 1=1"
        params = []
        if user_role != "admin":
            query += " AND user_id = ?"
            params.append(user_id)
            query += " AND NOT (resource_type = 'user' AND (event_type = 'create' OR event_type = 'delete'))"
        if start_ts:
            query += " AND timestamp >= ?"
            params.append(start_ts)
        if end_ts:
            query += " AND timestamp <= ?"
            params.append(end_ts)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()

        events = []
        for event_type, resource_type, resource_name, timestamp, details in rows:
            try:
                details_obj = json.loads(details) if details else {}
            except Exception:
                details_obj = {}
            events.append({
                "event_type": event_type,
                "resource_type": resource_type,
                "resource_name": resource_name,
                "timestamp": timestamp,
                "details": details_obj,
            })

        events.reverse()
        return jsonify({"events": events})
    except Exception as e:
        app.logger.error(f"Failed to load dashboard activity data: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/certs/state")
@login_required
def certs_state():
    """
    Lightweight state endpoint for polling certificate changes.
    Returns total count and max(id); clients can refresh when they change.
    """
    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            row = conn.execute("SELECT COUNT(*) as cnt, IFNULL(MAX(id), 0) as max_id FROM certificates").fetchone()
        return jsonify({"count": row[0], "max_id": row[1]})
    except Exception as e:
        app.logger.error(f"Failed to fetch certificate state: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/sign")
@login_required
def sign():
    try:
        # 1) Fetch raw rows
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            if hasattr(current_user, 'is_admin') and current_user.is_admin():
                csr_requests = conn.execute(
                    "SELECT id, name, csr_pem, created_at FROM csrs ORDER BY created_at DESC, id DESC"
                ).fetchall()
            else:
                csr_requests = conn.execute(
                    "SELECT id, name, csr_pem, created_at FROM csrs WHERE user_id = ? ORDER BY created_at DESC, id DESC",
                    (current_user.id,)
                ).fetchall()

        # Format timestamps to trim microseconds for display
        def _fmt_created(ts_val):
            if not ts_val:
                return ""
            try:
                return datetime.fromisoformat(ts_val).strftime("%Y-%m-%d %H:%M")
            except Exception:
                return str(ts_val).split(".")[0]

        csr_requests = [
            (row[0], row[1], row[2], _fmt_created(row[3]))
            for row in csr_requests
        ]

        mgr = get_ra_policy_manager()
        if current_user.is_admin():
            ra_policies = mgr.list_all_policies()
        else:
            ra_policies = mgr.list_policies_for_user(current_user.id)
        selected_policy = ra_policies[0] if ra_policies else None
        validity_days = mgr.get_validity_days(selected_policy)

        return render_template(
            "sign.html",
            csr_requests=csr_requests,
            ra_policies=ra_policies,
            selected_policy=selected_policy,
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

    prof = Profile.query.filter_by(name=filename).first()
    if not prof or not prof.content:
        return "Profile not found", 404
    
    return prof.content, 200, {'Content-Type': 'text/plain; charset=utf-8'}

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

def convert_public_key_formats(pem_path):
    formats = {
        "openssh": None,
        "rfc4716": None,
        "errors": {}
    }
    if not shutil.which("ssh-keygen"):
        formats["errors"]["openssh"] = "ssh-keygen is not available on PATH."
        return formats
    try:
        fallback_err = None
        openssh_proc = subprocess.run(
            ["ssh-keygen", "-i", "-m", "PKCS8", "-f", pem_path],
            capture_output=True,
            text=True
        )
        openssh_pub = openssh_proc.stdout.strip()
        if openssh_proc.returncode != 0 or not openssh_pub:
            try:
                openssh_pub = subprocess.run(
                    ["ssh-keygen", "-i", "-m", "PEM", "-f", pem_path],
                    check=True,
                    capture_output=True,
                    text=True
                ).stdout.strip()
            except subprocess.CalledProcessError as e:
                fallback_err = e
                openssh_pub = None

        if not openssh_pub:
            try:
                with open(pem_path, "rb") as f:
                    key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )
                openssh_pub = key.public_bytes(
                    Encoding.OpenSSH,
                    PublicFormat.OpenSSH
                ).decode("utf-8")
            except Exception as e:
                err = None
                if fallback_err:
                    err = (fallback_err.stderr or fallback_err.stdout or "ssh-keygen failed").strip()
                if not err:
                    err = str(e).strip() or "Public key conversion failed"
                formats["errors"]["openssh"] = err
                return formats
        if openssh_pub:
            formats["openssh"] = openssh_pub
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pub") as tmp_pub:
                tmp_pub.write((openssh_pub + "\n").encode("utf-8"))
                tmp_pub_path = tmp_pub.name
            try:
                rfc4716_pub = subprocess.run(
                    ["ssh-keygen", "-e", "-m", "RFC4716", "-f", tmp_pub_path],
                    check=True,
                    capture_output=True,
                    text=True
                ).stdout.strip()
                if rfc4716_pub:
                    formats["rfc4716"] = rfc4716_pub
            finally:
                os.unlink(tmp_pub_path)
    except subprocess.CalledProcessError as e:
        err = (e.stderr or e.stdout or "ssh-keygen failed").strip()
        formats["errors"]["openssh"] = err
    return formats

def build_cert_public_key_formats(cert):
    public_pem = cert.public_key().public_bytes(
        Encoding.PEM,
        PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    formats = {
        "public_pem": public_pem,
        "openssh": None,
        "rfc4716": None,
        "errors": {}
    }
    try:
        openssh_bytes = cert.public_key().public_bytes(
            Encoding.OpenSSH,
            PublicFormat.OpenSSH
        )
        formats["openssh"] = openssh_bytes.decode("utf-8")
    except Exception as e:
        formats["errors"]["openssh"] = f"OpenSSH conversion failed: {e}"

    if formats["openssh"]:
        if not shutil.which("ssh-keygen"):
            formats["errors"]["openssh"] = "ssh-keygen is not available on PATH."
        else:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pub") as tmp_pub:
                tmp_pub.write((formats["openssh"] + "\n").encode("utf-8"))
                tmp_pub_path = tmp_pub.name
            try:
                rfc4716_pub = subprocess.run(
                    ["ssh-keygen", "-e", "-m", "RFC4716", "-f", tmp_pub_path],
                    check=True,
                    capture_output=True,
                    text=True
                ).stdout.strip()
                if rfc4716_pub:
                    formats["rfc4716"] = rfc4716_pub
            except subprocess.CalledProcessError as e:
                err = (e.stderr or e.stdout or "ssh-keygen failed").strip()
                formats["errors"]["openssh"] = err
            finally:
                os.unlink(tmp_pub_path)
    return formats

def build_cert_base64(cert):
    der = cert.public_bytes(Encoding.DER)
    return base64.encodebytes(der).decode("ascii").strip()

def is_pqc_public_key(cert_details):
    algo = cert_details.get("Public Key Algorithm", "")
    return algo not in ("RSA", "EC", "") and algo is not None

def is_ssh2_supported(cert_details):
    algo = cert_details.get("Public Key Algorithm", "")
    params = cert_details.get("Public Key Parameters", "")
    if algo not in ("RSA", "EC"):
        return False
    if algo == "EC" and str(params).lower() == "secp256k1":
        return False
    return True

def convert_private_key_formats(pem_path):
    formats = {
        "pkcs1": None,
        "sec1": None,
        "errors": {}
    }
    rsa_proc = subprocess.run(
        ["openssl", "rsa", "-in", pem_path, "-traditional"],
        capture_output=True,
        text=True
    )
    if rsa_proc.returncode == 0 and rsa_proc.stdout.strip():
        formats["pkcs1"] = rsa_proc.stdout.strip()
        return formats
    ec_proc = subprocess.run(
        ["openssl", "ec", "-in", pem_path],
        capture_output=True,
        text=True
    )
    if ec_proc.returncode == 0 and ec_proc.stdout.strip():
        formats["sec1"] = ec_proc.stdout.strip()
        return formats
    err = (rsa_proc.stderr or ec_proc.stderr or "OpenSSL failed").strip()
    if err:
        formats["errors"]["private_formats"] = err
    return formats


@app.route("/inspect", methods=["GET", "POST"])
@login_required
def inspect():
    result = None
    formats = None

    if request.method == "POST":
        data = request.form.get("inspect_data", "").strip()
        include_formats = request.form.get("show_formats") == "on"
        result, formats = inspect_logic.run_inspect(
            data,
            DER_TYPES,
            convert_public_key_formats,
            convert_private_key_formats,
            build_cert_public_key_formats,
            certificate_to_dict,
            is_pqc_public_key,
            is_ssh2_supported,
            logger=app.logger,
            include_formats=include_formats
        )

    return render_template("inspect.html",
                           result=result,
                           formats=formats,
                           include_formats=include_formats if request.method == "POST" else False,
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


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/license")
def license_file():
    license_path = Path(current_app.root_path) / "LICENSE.md"
    if not license_path.exists():
        abort(404)
    return send_file(license_path, mimetype="text/markdown")


# ---------- Validity Endpoint ----------

@app.route("/update_validity", methods=["POST"])
@login_required
def update_validity():
    policy_id = request.form.get("policy_id")
    new_validity = request.form.get("validity_days", DEFAULT_VALIDITY_DAYS).strip()
    mgr, policy = _resolve_ra_policy(policy_id, current_user.id)
    if not policy:
        flash("Policy not found", "error")
        return redirect("/")
    try:
        mgr.update_validity(new_validity, policy_id=policy["id"])
        flash(f"Validity period updated to {new_validity} days for policy {policy['name']}", "success")
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
    # Work against the user's default RA policy (or system default if none)
    mgr, policy = _resolve_ra_policy(None, current_user.id)
    if not policy:
        policy = {
            "name": f"server_ext_{current_user.id}.cnf",
            "ext_config": "",
            "validity_period": DEFAULT_VALIDITY_DAYS,
            "type": "user",
            "id": None,
        }

    manual_config = policy.get("ext_config") or ""

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
            target_type = "system" if (save_system and current_user.is_admin()) else "user"
            target_user = None if target_type == "system" else current_user.id
            policy_name = policy.get("name") or f"server_ext_{current_user.id}.cnf"
            mgr.upsert_policy(
                name=policy_name,
                ext_config=new_config,
                validity_period=policy.get("validity_period", DEFAULT_VALIDITY_DAYS),
                policy_type=target_type,
                user_id=target_user,
            )
            if target_type == "system":
                flash("Configuration saved as system default.", "success")
            else:
                flash("Configuration saved as your user default.", "success")
            return redirect(url_for("server_ext"))
    if current_user.is_admin():
        profiles = Profile.query.order_by(Profile.id.desc()).all()
    else:
        profiles = Profile.query.filter_by(user_id=current_user.id).order_by(Profile.id.desc()).all()
    return render_template(
        "server_ext.html",
        server_ext_config=manual_config,
        profiles=profiles,
        is_admin=current_user.is_admin(),
        policy=policy,
    )


@app.route("/ra_policies")
@login_required
def ra_policies_page():
    mgr = get_ra_policy_manager()
    if current_user.is_admin():
        policies = mgr.list_all_policies()
    else:
        policies = mgr.list_policies_for_user(current_user.id, include_system=True)
    from flask import current_app
    challenge_password_enabled = current_app.config.get("SCEP_CHALLENGE_PASSWORD_ENABLED", False)
    return render_template("ra_policies.html", policies=policies, is_admin=current_user.is_admin(), challenge_password_enabled=challenge_password_enabled)


@app.route("/ra_policies/state")
@login_required
def ra_policies_state():
    try:
        if current_user.is_admin():
            query = "SELECT COUNT(*) as cnt, IFNULL(MAX(id),0) as max_id FROM ra_policies"
            params = ()
        else:
            query = "SELECT COUNT(*) as cnt, IFNULL(MAX(id),0) as max_id FROM ra_policies WHERE type='user' AND user_id = ?"
            params = (current_user.id,)
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            row = conn.execute(query, params).fetchone()
        return jsonify({"count": row[0], "max_id": row[1]})
    except Exception as e:
        app.logger.error(f"Failed to fetch RA policy state: {e}")
        return jsonify({"error": str(e)}), 500


def _get_profile_options():
    if current_user.is_admin():
        return Profile.query.order_by(Profile.id.desc()).all()
    return Profile.query.filter_by(user_id=current_user.id).order_by(Profile.id.desc()).all()


@app.route("/ra_policies/new", methods=["GET", "POST"])
@login_required
def ra_policy_new():
    mgr = get_ra_policy_manager()
    profiles = _get_profile_options()
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        validity = (request.form.get("validity") or DEFAULT_VALIDITY_DAYS).strip()
        ext_config = request.form.get("ext_config") or ""
        profile_name = request.form.get("profile_name")
        policy_type = "system" if (current_user.is_admin() and request.form.get("is_system") == "on") else "user"
        user_id = None if policy_type == "system" else current_user.id
        est_default = current_user.is_admin() and request.form.get("is_est_default") == "on"
        scep_default = current_user.is_admin() and request.form.get("is_scep_default") == "on"

        if not name:
            flash("Policy name is required", "danger")
            return render_template("ra_policy_form.html", profiles=profiles, is_admin=current_user.is_admin(), mode="new")

        if profile_name:
            prof = Profile.query.filter_by(name=profile_name).first()
            if prof and prof.content:
                ext_config = prof.content


        try:
            mgr.upsert_policy(
                name=name,
                ext_config=ext_config,
                validity_period=validity,
                restrictions="",
                policy_type=policy_type,
                user_id=user_id,
                est_default=est_default,
                scep_default=scep_default,
            )
            # Event logging
            try:
                from events import log_event
                log_event(
                    event_type="create",
                    resource_type="policy",
                    resource_name=name,
                    user_id=current_user.id,
                    details={"policy_type": policy_type}
                )
            except Exception:
                pass
            flash("Policy created", "success")
            return redirect(url_for("ra_policies_page"))
        except Exception as e:
            flash(f"Error creating policy: {e}", "danger")

    return render_template("ra_policy_form.html", profiles=profiles, is_admin=current_user.is_admin(), mode="new")


def _load_policy_for_edit(policy_id: int):
    mgr = get_ra_policy_manager()
    policy = mgr.get_policy(policy_id=policy_id)
    if not policy:
        abort(404)
    view_only = False
    if not current_user.is_admin():
        if policy["type"] == "system":
            if request.method == "GET":
                view_only = True
            else:
                abort(403)
        elif policy.get("user_id") != current_user.id:
            abort(403)
    return mgr, policy, view_only


@app.route("/ra_policies/<int:policy_id>/edit", methods=["GET", "POST"])
@login_required
def ra_policy_edit(policy_id):
    mgr, policy, view_only = _load_policy_for_edit(policy_id)
    # Allow explicit view-only mode via querystring
    if request.args.get("view") == "1":
        view_only = True
    if request.method == "POST" and view_only:
        abort(403)
    profiles = _get_profile_options()
    if request.method == "POST":
        validity = (request.form.get("validity") or policy.get("validity_period") or DEFAULT_VALIDITY_DAYS).strip()
        ext_config = request.form.get("ext_config") or policy.get("ext_config") or ""
        profile_name = request.form.get("profile_name")
        est_default = current_user.is_admin() and request.form.get("is_est_default") == "on"
        scep_default = current_user.is_admin() and request.form.get("is_scep_default") == "on"
        new_type = policy.get("type")
        if current_user.is_admin():
            new_type = "system" if request.form.get("is_system") == "on" else "user"

        if profile_name:
            prof = Profile.query.filter_by(name=profile_name).first()
            if prof and prof.content:
                ext_config = prof.content


        try:
            mgr.update_policy(policy_id, ext_config=ext_config, validity_period=validity, policy_type=new_type, est_default=est_default, scep_default=scep_default)
            # Event logging
            try:
                from events import log_event
                log_event(
                    event_type="update",
                    resource_type="policy",
                    resource_name=policy.get("name", str(policy_id)),
                    user_id=current_user.id,
                    details={}
                )
            except Exception:
                pass
            flash("Policy updated", "success")
            return redirect(url_for("ra_policies_page"))
        except Exception as e:
            flash(f"Error updating policy: {e}", "danger")

    return render_template("ra_policy_form.html", profiles=profiles, is_admin=current_user.is_admin(), mode="edit", policy=policy, view_only=view_only)


@app.route("/ra_policies/<int:policy_id>/delete", methods=["POST"])
@login_required
def ra_policy_delete(policy_id):
    mgr, policy, _ = _load_policy_for_edit(policy_id)
    try:
        mgr.delete_policy(policy_id)
        # Event logging
        try:
            from events import log_event
            log_event(
                event_type="delete",
                resource_type="policy",
                resource_name=policy.get("name", str(policy_id)),
                user_id=current_user.id,
                details={}
            )
        except Exception:
            pass
        flash("Policy deleted", "success")
    except Exception as e:
        flash(f"Error deleting policy: {e}", "danger")
    return redirect(url_for("ra_policies_page"))

@app.route("/view_root")
def view_root():
    try:
        with open(app.config["ROOT_CERT_PATH"], "r") as f:
            cert_pem = f.read()
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        cert_details = certificate_to_dict(cert)
        raw_cert = cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")
        raw_cert_b64 = build_cert_base64(cert)
        cert_text = get_certificate_text(raw_cert)
        pub_formats = build_cert_public_key_formats(cert)
        is_pqc_key = is_pqc_public_key(cert_details)
        is_ssh2_key = is_ssh2_supported(cert_details)
        return render_template(
            "view.html",
            cert_details=cert_details,
            raw_cert=raw_cert,
            raw_cert_b64=raw_cert_b64,
            cert_text=cert_text,
            public_key_pem=pub_formats["public_pem"],
            public_key_openssh=pub_formats["openssh"],
            public_key_rfc4716=pub_formats["rfc4716"],
            public_key_errors=pub_formats["errors"],
            is_pqc_key=is_pqc_key,
            is_ssh2_key=is_ssh2_key
        )
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
        raw_cert_b64 = build_cert_base64(cert)
        cert_text = get_certificate_text(raw_cert)
        pub_formats = build_cert_public_key_formats(cert)
        is_pqc_key = is_pqc_public_key(cert_details)
        is_ssh2_key = is_ssh2_supported(cert_details)
        return render_template(
            "view.html",
            cert_details=cert_details,
            raw_cert=raw_cert,
            raw_cert_b64=raw_cert_b64,
            cert_text=cert_text,
            public_key_pem=pub_formats["public_pem"],
            public_key_openssh=pub_formats["openssh"],
            public_key_rfc4716=pub_formats["rfc4716"],
            public_key_errors=pub_formats["errors"],
            is_pqc_key=is_pqc_key,
            is_ssh2_key=is_ssh2_key
        )
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
                    "SELECT id, subject, serial, revoked, cert_pem, issued_via FROM certificates WHERE id = ?",
                    (cert_id,)
                )
            else:
                cur = conn.execute(
                    "SELECT id, subject, serial, revoked, cert_pem, issued_via FROM certificates WHERE id = ? AND user_id = ?",
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
        raw_cert_b64 = build_cert_base64(cert)
        cert_text = get_certificate_text(raw_cert)
        pub_formats = build_cert_public_key_formats(cert)
        is_pqc_key = is_pqc_public_key(cert_details)
        is_ssh2_key = is_ssh2_supported(cert_details)
        return render_template(
            "view.html",
            cert_details=cert_details,
            raw_cert=raw_cert,
            raw_cert_b64=raw_cert_b64,
            cert_text=cert_text,
            issued_via=row["issued_via"] if row and "issued_via" in row.keys() else "unknown",
            public_key_pem=pub_formats["public_pem"],
            public_key_openssh=pub_formats["openssh"],
            public_key_rfc4716=pub_formats["rfc4716"],
            public_key_errors=pub_formats["errors"],
            is_pqc_key=is_pqc_key,
            is_ssh2_key=is_ssh2_key
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
        now = datetime.utcnow()
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
    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            # Fetch serial and subject before deletion
            cur = conn.execute("SELECT serial, subject, issued_via FROM certificates WHERE id = ?", (cert_id,))
            cert_row = cur.fetchone()
            serial = cert_row[0] if cert_row else str(cert_id)
            subject = cert_row[1] if cert_row else None
            issued_via = cert_row[2] if cert_row else None
            # Delete certificate
            if current_user.is_admin():
                del_cur = conn.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
            else:
                del_cur = conn.execute("DELETE FROM certificates WHERE id = ? AND user_id = ?", (cert_id, current_user.id))
            conn.commit()
            app.logger.info(f"[DELETE] Rows deleted for cert {cert_id}: {del_cur.rowcount}")
            # Event logging
            from events import log_event
            log_event(
                event_type="delete",
                resource_type="certificate",
                resource_name=serial,
                user_id=current_user.id,
                details={"subject": subject, "issued_via": issued_via, "rowcount": del_cur.rowcount} if subject else {"rowcount": del_cur.rowcount}
            )
    except Exception as e:
        app.logger.error(f"[DELETE] Failed to delete certificate ID {cert_id}: {str(e)}")

    # Always back to /certs (success or failure)
    return redirect("/certs")




@app.route("/submit", methods=["POST"])
@login_required
def submit():
    app.logger.debug("submit: Received CSR signing request")
    csr_input = request.form["csr"]
    app.logger.debug(f"submit: ext_block={request.form.get('ext_block', 'v3_ext')}")
    ext_block = request.form.get("ext_block", "v3_ext")
    policy_id = request.form.get("policy_id")
    app.logger.debug(f"submit: policy_id={policy_id}")
    mgr, policy = _resolve_ra_policy(policy_id, current_user.id)
    app.logger.debug(f"submit: Resolved policy={policy}")
    if not policy:
        app.logger.error("submit: No RA policy available for signing.")
        flash("No RA policy available for signing.", "error")
        return redirect("/")
    try:
        app.logger.debug("submit: Attempting to parse CSR")
        csr_pem = normalize_csr_pem_text(csr_input)
        csr_obj = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        subject_str = ", ".join([f"{attr.oid._name}={attr.value}" for attr in csr_obj.subject])
        app.logger.debug(f"submit: Parsed CSR subject: {subject_str}")
    except Exception as e:
        subject_str = "Unknown Subject"
        app.logger.error(f"submit: Failed to parse CSR: {e}")
        flash(f"Invalid CSR: {e}", "error")
        return redirect("/")

    # ...removed strict CN validation...

    # Use selected policy if available, otherwise fallback to EST default
    if not policy:
        policy = mgr.get_protocol_default("est")
        app.logger.debug(f"submit: No policy selected, using EST protocol default policy: {policy}")
    else:
        app.logger.debug(f"submit: Using selected enrollment policy: {policy}")
    validity_days = mgr.get_validity_days(policy)
    app.logger.debug(f"submit: Validity days from policy: {validity_days}")
    try:
        validity_int = int(str(validity_days))
        app.logger.debug(f"submit: Parsed validity_int={validity_int}")
    except Exception:
        validity_int = int(DEFAULT_VALIDITY_DAYS)
        app.logger.debug(f"submit: Using DEFAULT_VALIDITY_DAYS={DEFAULT_VALIDITY_DAYS}")

    # Always log the OpenSSL command that would be used for signing
    # Always log the OpenSSL command that would be used for signing
    with mgr.temp_extfile(policy) as extfile_path:
        openssl_cmd_preview = None
        if extfile_path:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".csr") as csr_file:
                csr_file.write(csr_pem.encode())
                csr_filename = csr_file.name
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
                cert_filename = cert_file.name
            custom_serial = secrets.randbits(64)
            custom_serial_str = hex(custom_serial)
            openssl_cmd = ["openssl", "x509"]
            openssl_cmd.extend(get_provider_args())
            openssl_cmd.extend(["-req",
                "-in", csr_filename,
                "-CA", app.config["SUBCA_CERT_PATH"],
                "-CAkey", app.config["SUBCA_KEY_PATH"],
                "-set_serial", custom_serial_str, 
                "-CAcreateserial",
                "-days", str(validity_int),
                "-out", cert_filename,
                "-extfile", extfile_path,
                "-extensions", ext_block
            ])
            openssl_cmd_preview = ' '.join(openssl_cmd)
            app.logger.debug(f"[L1997] submit: OpenSSL command preview: {openssl_cmd_preview}")
            # for tests4: do not unlink temp files so they can be used for manual OpenSSL testing
            # os.unlink(csr_filename)
            # os.unlink(cert_filename)
    if app.config.get("VAULT_ENABLED", False):
        try:
            app.logger.debug("submit: Attempting to create CA instance (Vault enabled)")
            ca = get_ca_instance()
            app.logger.debug(f"submit: CA instance created: vault_enabled={ca._vault_enabled if hasattr(ca, '_vault_enabled') else 'N/A'}")
            app.logger.debug("submit: Signing certificate using CA class")
            cert_obj = ca.sign(csr_obj, days=validity_int)
            app.logger.debug("submit: Certificate signed, serial=%s", hex(cert_obj.serial_number))
            cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            actual_serial = hex(cert_obj.serial_number)
            app.logger.info(f"Certificate signed successfully via CA class: serial={actual_serial}")
        except Exception as e:
            app.logger.error(f"submit: Vault CA signing failed: {e}")
            flash(f"Vault CA signing failed: {e}", "error")
            return redirect("/")
    else:
        with mgr.temp_extfile(policy) as extfile_path:
            app.logger.trace(f"submit: Using extfile_path={extfile_path}")
            if not extfile_path:
                app.logger.error("submit: No RA policy extension configuration available.")
                flash("No RA policy extension configuration available.", "error")
                return redirect("/")
            with tempfile.NamedTemporaryFile(delete=False, suffix=".csr") as csr_file:
                csr_file.write(csr_pem.encode())
                csr_filename = csr_file.name
                app.logger.trace(f"submit: CSR written to temp file {csr_filename}")
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
                cert_filename = cert_file.name
                app.logger.trace(f"submit: Cert will be written to temp file {cert_filename}")
            custom_serial = secrets.randbits(64)
            custom_serial_str = hex(custom_serial)
            app.logger.trace(f"submit: Generated custom serial {custom_serial_str}")
            cmd = ["openssl", "x509"]
            cmd.extend(get_provider_args())
            cmd.extend(["-req",
                "-in", csr_filename,
                "-CA", app.config["SUBCA_CERT_PATH"],
                "-CAkey", app.config["SUBCA_KEY_PATH"],
                "-set_serial", custom_serial_str, 
                "-CAcreateserial",
                "-days", str(validity_int),
                "-out", cert_filename,
                "-extfile", extfile_path,
                "-extensions", ext_block
            ])
            app.logger.trace(f"[L2009] submit: OpenSSL command: {' '.join(cmd)}")
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                app.logger.trace(f"[L2011] submit: OpenSSL command executed successfully")
            except subprocess.CalledProcessError as e:
                os.unlink(csr_filename)
                os.unlink(cert_filename)
                error_msg = f"Error during OpenSSL signing: {e.stderr}"
                app.logger.error(f"submit: {error_msg}")
                flash(error_msg, "error")
                return redirect("/")
            with open(cert_filename, "r") as f:
                cert_pem = f.read()
                app.logger.trace(f"[L2016] submit: Read signed cert from {cert_filename}, length={len(cert_pem)}")
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            actual_serial = hex(cert_obj.serial_number)
            app.logger.trace(f"[L2018] submit: Loaded cert object, serial={actual_serial}")
            # Copy extfile_path to a permanent location for manual inspection
            import shutil
            extfile_copy_path = extfile_path + ".copy.cnf"
            shutil.copy(extfile_path, extfile_copy_path)
            app.logger.info(f"[L2034] submit: extfile config copied for manual inspection: {extfile_copy_path}")
            # Unlink extfile_path after copying for cleanup
            os.unlink(extfile_path)
    app.logger.debug(f"submit: Saving certificate to database, serial={actual_serial}")
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute(
            "INSERT INTO certificates (subject, serial, cert_pem, user_id, issued_via) VALUES (?, ?, ?, ?, ?)",
            (subject_str, actual_serial, cert_pem, current_user.id, 'ui')
        )
    app.logger.debug(f"submit: Certificate saved to DB for user_id={current_user.id}")
    # Event logging
    from events import log_event
    log_event(
        event_type="create",
        resource_type="certificate",
        resource_name=actual_serial,
        user_id=current_user.id,
        details={"subject": subject_str}
    )
    app.logger.debug(f"submit: Event logged for certificate creation, serial={actual_serial}")
    flash(f"Certificate signed successfully! Serial: {actual_serial}", "success")
    app.logger.debug("submit: Redirecting to home page after successful signing")
    return redirect("/")

@app.route("/submit_q", methods=["POST"])
def submit_q():
    csr_input = request.form["csr"]
    ext_block = request.form.get("ext_block", "v3_ext")
    policy_id = request.form.get("policy_id")
    mgr, policy = _resolve_ra_policy(policy_id, None)
    if not policy:
        return "No RA policy available", 400
    try:
        csr_pem = normalize_csr_pem_text(csr_input)
        csr_obj = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        subject_str = ", ".join([f"{attr.oid._name}={attr.value}" for attr in csr_obj.subject])
    except Exception as e:
        subject_str = "Unknown Subject"
        app.logger.error(f"submit_q: Failed to parse CSR: {e}")
        return f"Invalid CSR: {e}", 400

    # ...removed strict CN validation...
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csr") as csr_file:
        csr_file.write(csr_pem.encode())
        csr_filename = csr_file.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
        cert_filename = cert_file.name

    custom_serial = secrets.randbits(64)
    # Format it as a hexadecimal string (with the 0x prefix)
    custom_serial_str = hex(custom_serial)


    validity_days = mgr.get_validity_days(policy)
    try:
        validity_int = int(str(validity_days))
    except Exception:
        validity_int = int(DEFAULT_VALIDITY_DAYS)

    try:
        with mgr.temp_extfile(policy) as extfile_path:
            if not extfile_path:
                return "No extension config available", 400
            cmd = ["openssl", "x509"]
            cmd.extend(get_provider_args())
            cmd.extend(["-req",
                "-in", csr_filename,
                "-CA", app.config["SUBCA_CERT_PATH"],
                "-signkey", app.config["SUBCA_KEY_PATH"],
                "-set_serial", custom_serial_str,
                "-CAcreateserial",
                "-days", validity_int,
                "-out", cert_filename,
                "-extfile", extfile_path,
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
        conn.execute(
            "INSERT INTO certificates (subject, serial, cert_pem, user_id, issued_via) VALUES (?, ?, ?, ?, ?)",
            (subject_str, serial_hex, full_chain_pem, current_user.id, 'ui')
        )
    # Event logging
    from events import log_event
    log_event(
        event_type="create",
        resource_type="certificate",
        resource_name=serial_hex,
        user_id=current_user.id,
        details={"subject": subject_str}
    )
    os.unlink(csr_filename)
    os.unlink(cert_filename)
    return redirect("/")


@app.route("/revoke/<int:cert_id>", methods=["POST"])
@login_required
def revoke(cert_id):
    from flask import flash
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        if current_user.is_admin():
            conn.execute("UPDATE certificates SET revoked = 1 WHERE id = ?", (cert_id,))
        else:
            conn.execute("UPDATE certificates SET revoked = 1 WHERE id = ? AND user_id = ?", (cert_id, current_user.id))
        conn.commit()
        app.logger.info(f"[REVOKE] Certificate {cert_id} revoked.")
        # Event logging
        from events import log_event
        # Fetch the certificate serial number for logging
        cur = conn.execute("SELECT serial, subject FROM certificates WHERE id = ?", (cert_id,))
        cert_row = cur.fetchone()
        serial = cert_row[0] if cert_row else str(cert_id)
        subject = cert_row[1] if cert_row else None
        log_event(
            event_type="revoke",
            resource_type="certificate",
            resource_name=serial,
            user_id=current_user.id,
            details={"subject": subject} if subject else {}
        )
    flash("Certificate revoked", "success")
    update_crl()
    return redirect("/certs")





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
    
    now = datetime.datetime.now(datetime.UTC)
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
                    app.logger.debug(f"OCSP: serial {hex(serial_number)} not found; returning UNAUTHORIZED")
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
                status_str = "REVOKED" if revoked else "GOOD"
                app.logger.debug(f"OCSP: serial {hex(serial_number)} status {status_str}")

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
    if raw.strip().startswith(b"-----BEGIN CERTIFICATE REQUEST-----") or raw.strip().startswith(b"-----BEGIN NEW CERTIFICATE REQUEST-----"):
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

def normalize_csr_pem_text(csr_text: str) -> str:
    if not csr_text or not csr_text.strip():
        raise ValueError("CSR is empty")
    raw = csr_text.strip().encode("utf-8")
    der = normalize_to_der(raw)
    return (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        + base64.encodebytes(der).decode("ascii")
        + "-----END CERTIFICATE REQUEST-----\n"
    )



@app.route("/.well-known/est/simpleenroll", methods=["POST"])
def est_enroll():
    raw = request.get_data()
    ext_block = request.form.get("ext_block", "v3_ext")
    mgr, policy = _resolve_ra_policy(None, None)

    # 1) Normalize CSR to DER, then convert to PEM for CA class
    try:
        der_csr = normalize_to_der(raw)
        # Convert DER to PEM format
        pem_csr = (
            b"-----BEGIN CERTIFICATE REQUEST-----\n" +
            base64.encodebytes(der_csr) +
            b"-----END CERTIFICATE REQUEST-----\n"
        )
        csr_obj = x509.load_pem_x509_csr(pem_csr, default_backend())
    except Exception as e:
        app.logger.error(f"Invalid CSR encoding: {e}")
        return "Invalid CSR encoding", 400

    # ...removed strict CN validation...

    validity_days = mgr.get_validity_days(policy)
    try:
        validity_int = int(str(validity_days))
    except Exception:
        validity_int = int(DEFAULT_VALIDITY_DAYS)


    ca = get_ca_instance()
    vault_mode = getattr(ca, '_vault_enabled', False)
    if vault_mode:
        try:
            app.logger.debug(f"EST: Signing CSR with CA class (ttl={validity_int} hours) [Vault mode]")
            cert = ca.sign(csr_obj, ttl=validity_int)
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        except Exception as e:
            app.logger.error(f"EST: Vault CA signing failed: {e}")
            return f"Vault CA signing failed: {e}", 500
    else:
        # Use OpenSSL CLI for signing
        app.logger.debug("EST: Vault not enabled, using OpenSSL CLI for signing.")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csr") as csr_file:
            csr_file.write(der_csr)
            csr_der_filename = csr_file.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
            cert_filename = cert_file.name

        custom_serial_str = hex(secrets.randbits(64))

        with mgr.temp_extfile(policy) as extfile_path:
            if not extfile_path:
                app.logger.error(f"EST: extfile_path is None. CSR file: {csr_der_filename}, Cert file: {cert_filename}")
                return "No extension config available", 400
            # Ensure all arguments are strings
            cmd = [
                str("openssl"), str("x509"), str("-req"),
                str("-inform"), str("DER"),
                str("-in"), str(csr_der_filename),
                str("-CA"), str(app.config["SUBCA_CERT_PATH"]),
                str("-CAkey"), str(app.config["SUBCA_KEY_PATH"]),
                str("-set_serial"), str(custom_serial_str),
                str("-days"), str(validity_int),
                str("-out"), str(cert_filename),
                str("-extfile"), str(extfile_path),
                str("-extensions"), str(ext_block)
            ]
            app.logger.debug(f"EST: OpenSSL CLI command: {cmd}")
            subprocess.run(cmd, check=True, capture_output=True, text=True)

        with open(cert_filename, "r") as f:
            cert_pem = f.read()
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        # Cleanup temp files
        try:
            os.unlink(csr_der_filename)
            os.unlink(cert_filename)
        except Exception:
            pass

    # 4) Record in the database
    subject_str = ", ".join(f"{attr.oid._name}={attr.value}" for attr in cert.subject)
    actual_serial = hex(cert.serial_number)
    from flask_login import current_user
    
    # Use current_user.id if authenticated, otherwise None
    user_id = current_user.id if current_user.is_authenticated else None
    
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute(
            "INSERT INTO certificates (subject, serial, cert_pem, user_id, issued_via) VALUES (?, ?, ?, ?, ?)",
            (subject_str, actual_serial, cert_pem, user_id, 'est')
        )

    # Event logging for EST enrollment
    try:
        from events import log_event
        log_event(
            event_type="create",
            resource_type="certificate",
            resource_name=actual_serial,
            user_id=user_id if user_id is not None else "est",
            details={"subject": subject_str}
        )
    except Exception as e:
        app.logger.error(f"Failed to log EST certificate event: {e}")

    # 5) Write the signed cert to a file (for pkcs7 conversion)
    signed_cert_path = os.path.join("pki-misc", "est_signed_cert.pem")
    with open(signed_cert_path, "wb") as f:
        f.write(cert_pem.encode())

    # 6) Build a PKCS#7 container **with only the issued certificate** (no chain)

    pkcs7_path = os.path.join("pki-misc", "est_cert_chain.p7")
    subprocess.run([
        "openssl", "crl2pkcs7",
        "-nocrl",
        "-certfile", signed_cert_path,
        "-outform", "DER",
        "-out", pkcs7_path
    ], check=True)

    # 7) Read, base64-encode, and return via make_response
    pkcs7_der = open(pkcs7_path, "rb").read()
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

@app.route("/account/theme", methods=["POST"])
@login_required
def account_theme():
    theme_style = request.form.get("theme_style", "modern").strip().lower()
    theme_color = request.form.get("theme_color", "snow").strip().lower()
    if theme_style not in ("modern", "classic"):
        theme_style = "classic"
    if theme_color not in ("snow", "midnight"):
        theme_color = "snow"
    if theme_style == "classic":
        theme_color = "snow"
    updated_style = set_user_theme_style(current_user.id, theme_style)
    updated_color = set_user_theme_color(current_user.id, theme_color)
    if updated_style and updated_color:
        flash("Theme updated.", "success")
    else:
        flash("Theme update failed. Run migrate_db.py to add the custom_columns field.", "warning")
    return redirect(url_for('account'))

@app.route("/change_password", methods=["POST"])
@login_required
def change_password():
    if getattr(current_user, 'auth_source', 'local') == 'ldap':
        flash('Cannot change password for LDAP users. Passwords are managed by your LDAP/Active Directory administrator.', 'warning')
        return redirect(url_for('account'))
    current_password = request.form.get("current_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()
    if not current_user.check_password(current_password):
        flash("Current password is incorrect.", "error")
        return redirect(url_for('account'))
    if not new_password or new_password != confirm_password:
        flash("New passwords do not match or are empty.", "error")
        return redirect(url_for('account'))
    # Update password using user_models logic for persistent user status
    from werkzeug.security import generate_password_hash
    import sqlite3
    db_path = app.config["DB_PATH"]
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), current_user.id))
    con.commit()
    con.close()
    # Optionally update status to 'active' if needed (persistent logic)
    # cur.execute("UPDATE users SET status = 'active' WHERE id = ?", (current_user.id,))
    # Log user event as 'reset_password' (for both user and admin resets)
    try:
        from events import log_user_event
        log_user_event('reset_password', current_user.id, {'by': current_user.id, 'username': current_user.username, 'actor_username': current_user.username})
    except Exception:
        pass
    flash("Password changed successfully.", "success")
    app.logger.info(f"User {current_user.username} changed their password.")
    return redirect(url_for('account'))



# ---------- Run Servers ----------
from werkzeug.serving import run_simple


from threading import Thread
from http.server import HTTPServer, SimpleHTTPRequestHandler


def run_http_general():
    app.run(host="0.0.0.0", port=HTTP_DEFAULT_PORT,use_reloader=False, use_debugger=True)

def run_https():
    app.run(host="0.0.0.0", port=HTTPS_PORT, ssl_context=(SSL_CERT_PATH, SSL_KEY_PATH), use_reloader=False, use_debugger=True)

def run_trusted_https():
    try:
        context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=TRUSTED_SSL_CERT_PATH, keyfile=TRUSTED_SSL_KEY_PATH)
        context.load_verify_locations(cafile=app.config["CHAIN_FILE_PATH"])
        context.verify_mode = ssl.CERT_REQUIRED  # Force client cert verification
        app.logger.info(f"Starting trusted HTTPS server on port {TRUSTED_HTTPS_PORT} with mTLS required.")
        app.run(host="0.0.0.0", port=TRUSTED_HTTPS_PORT, ssl_context=context, use_reloader=False, use_debugger=True)
    except Exception as e:
        app.logger.error(f"Error starting trusted HTTPS server: {e}", exc_info=True)
        print(f"Error starting trusted HTTPS server: {e}")


# —— Vault Integration ——
def init_vault_client():
    """
    Initialize Vault client from config.ini [VAULT] section.
    Returns None if Vault is disabled, allowing fallback to file-based keys.
    """
    global vault_client
    
    if not VAULT_CONFIG.get('enabled', False):
        app.logger.info("Vault integration is DISABLED (config.ini [VAULT] enabled=false)")
        app.logger.info("Using file-based keys from config.ini [CA] section")
        return None
    
    app.logger.info("Vault integration is ENABLED (config.ini [VAULT] enabled=true)")
    
    vault_addr = VAULT_CONFIG.get('address')
    if not vault_addr:
        raise RuntimeError("VAULT address must be set in config.ini when enabled=true")
    
    role_id = VAULT_CONFIG.get('role_id')
    secret_id = VAULT_CONFIG.get('secret_id')
    
    if not role_id or not secret_id:
        raise RuntimeError(
            "VAULT_ROLE_ID and VAULT_SECRET_ID must be set in environment "
            "or config.ini when VAULT enabled=true"
        )
    
    try:
        from vault_client import VaultClient
        
        # Create Vault client with settings from config.ini
        vault = VaultClient(
            vault_addr=vault_addr,
            role_id=role_id,
            secret_id=secret_id,
            verify_ssl=VAULT_CONFIG.get('verify_ssl', True),
            ca_cert=VAULT_CONFIG.get('ca_cert_path'),
            timeout=VAULT_CONFIG.get('timeout', 30)
        )
        
        if not vault.health_check():
            raise RuntimeError(f"Vault health check failed for {vault_addr}")
        
        app.logger.info(f"✓ Vault client connected to {vault_addr}")
        app.logger.info(f"  RSA PKI path: {VAULT_CONFIG['pki_rsa_path']}")
        app.logger.info(f"  EC PKI path: {VAULT_CONFIG['pki_ec_path']}")
        
        vault_client = vault
        app.config['VAULT_CLIENT'] = vault
        return vault
        
    except Exception as e:
        app.logger.error(f"Failed to initialize Vault: {e}")
        raise


def get_ca_instance():
    """
    Create CertificateAuthority instance based on config.ini settings.
    Automatically uses Vault or file-based keys depending on [VAULT] enabled setting.
    """
    from ca import CertificateAuthority
    
    ca_mode = app.config.get('CA_MODE', 'RSA')
    
    # Use the currently configured paths from app.config
    key_path = app.config.get('SUBCA_KEY_PATH')
    chain_path = app.config.get('CHAIN_FILE_PATH')
    
    app.logger.debug(f"get_ca_instance: ca_mode={ca_mode}, key_path={key_path}, chain_path={chain_path}")
    
    # Determine PKI path for Vault based on mode
    if ca_mode == 'EC':
        pki_path = VAULT_CONFIG.get('pki_ec_path')
    else:
        pki_path = VAULT_CONFIG.get('pki_rsa_path')
    
    if vault_client:
        # Vault mode (config.ini [VAULT] enabled=true)
        app.logger.debug(f"Creating CA in Vault mode: pki_path={pki_path}")
        return CertificateAuthority(
            chain_path=chain_path,
            vault_client=vault_client,
            pki_path=pki_path,
            default_role=VAULT_CONFIG.get('role_default', 'server-cert')
        )
    else:
        # Legacy mode (config.ini [VAULT] enabled=false)
        app.logger.debug(f"Creating CA in Legacy mode")
        return CertificateAuthority(
            key_path=key_path,
            chain_path=chain_path
        )


if __name__ == "__main__":
    # Initialize Vault if enabled
    try:
        init_vault_client()
        if vault_client:
            app.logger.info("Running in VAULT MODE - keys isolated in Vault")
        else:
            app.logger.info("Running in LEGACY MODE - using file-based keys")
    except Exception as e:
        app.logger.error(f"Failed to initialize Vault: {e}")
        app.logger.info("Falling back to LEGACY MODE - using file-based keys")
        vault_client = None
    
    # Initialize CRL on startup (creates empty CRL if no revoked certificates)
    try:
        update_crl()
        app.logger.info("CRL initialized successfully")
    except Exception as e:
        app.logger.warning(f"Failed to initialize CRL on startup: {e}")
    
    Thread(target=run_https).start()
    Thread(target=run_trusted_https).start()
    Thread(target=run_http_general, daemon=True).start()



