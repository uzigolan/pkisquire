import secrets
import hashlib
import math
from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request, session as flask_session, current_app
from flask_login import login_required, current_user, logout_user, login_user, user_logged_in, user_logged_out
import uuid
import sqlite3
import re
from datetime import datetime, timedelta, timezone
from user_models import get_all_users, get_username_by_id

users_bp = Blueprint('users', __name__, url_prefix='/users')

# --- Flask-Login Signal Handlers ---
def _now_utc_str():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# --- Load MAX_IDLE_TIME config on blueprint registration ---
def init_users_config(app, config):
    app.config["MAX_IDLE_TIME"] = config.get("DEFAULT", "max_idle_time", fallback="7d")
    app.config["API_TOKEN_DEFAULT_VALIDITY"] = config.get("DEFAULT", "api_token_default_validity", fallback="60d")
    app.config["API_TOKEN_LENGTH"] = config.getint("DEFAULT", "api_token_length", fallback=64)


def register_login_signals(app):

    @user_logged_in.connect_via(app)
    def track_user_logged_in(sender, user):
        current_app.logger.debug(f"track_user_logged_in: user_id={user.id} username={getattr(user, 'username', None)}")
        ensure_sessions_table()
        # Always generate a new sid on login to reset idle
        sid = str(uuid.uuid4())
        flask_session['sid'] = sid
        now_str = _now_utc_str()
        flask_session['last_activity'] = now_str
        current_app.logger.debug(f"track_user_logged_in: sid={sid} now_str={now_str}")
        db_path = current_app.config["DB_PATH"]
        current_app.logger.debug(f"track_user_logged_in: using DB_PATH={db_path}")
        with sqlite3.connect(db_path) as conn:
            # Always reset both login_time and last_activity to now on login
            conn.execute("INSERT OR REPLACE INTO user_sessions (session_id, user_id, login_time, last_activity) VALUES (?, ?, ?, ?)", (sid, user.id, now_str, now_str))
        current_app.logger.debug("track_user_logged_in: session row inserted/updated")

    @user_logged_out.connect_via(app)
    def track_user_logged_out(sender, user):
        current_app.logger.debug(f"track_user_logged_out: user_id={user.id} username={getattr(user, 'username', None)}")
        sid = flask_session.get('sid')
        if sid:
            current_app.logger.debug(f"track_user_logged_out: sid={sid}")
            db_path = current_app.config["DB_PATH"]
            current_app.logger.debug(f"track_user_logged_out: using DB_PATH={db_path}")
            with sqlite3.connect(db_path) as conn:
                conn.execute("DELETE FROM user_sessions WHERE session_id = ?", (sid,))
            flask_session.pop('sid', None)
            current_app.logger.debug("track_user_logged_out: session row deleted")



# --- Utility: Parse idle time config values like '20m', '1h', '4d' ---
def parse_idle_time(s):
    """
    Parse a string like '20m', '1h', '4d' into seconds.
    Supports:
      - m: minutes
      - h: hours
      - d: days
    Returns: int (seconds)
    """
    import re
    s = s.strip().lower()
    match = re.match(r"^(\d+)([mhd])$", s)
    if not match:
        raise ValueError(f"Invalid idle time format: {s}")
    value, unit = match.groups()
    value = int(value)
    if unit == 'm':
        return value * 60
    elif unit == 'h':
        return value * 3600
    elif unit == 'd':
        return value * 86400
    else:
        raise ValueError(f"Unknown unit: {unit}")

def parse_duration_generic(s):
    """
    Parse durations for token validity:
      - h: hours
      - d: days
      - m: months (30d)
      - y: years (365d)
    Returns seconds (int) or raises ValueError.
    """
    if not s:
        raise ValueError("Empty duration")
    s = s.strip().lower()
    match = re.match(r"^(\d+)([hdmy])$", s)
    if not match:
        raise ValueError(f"Invalid duration format: {s}")
    value, unit = match.groups()
    value = int(value)
    if unit == "h":
        return value * 3600
    if unit == "d":
        return value * 86400
    if unit == "m":
        return value * 86400 * 30
    if unit == "y":
        return value * 86400 * 365
    raise ValueError(f"Unknown duration unit: {unit}")

# --- API token helpers ---
def ensure_api_tokens_table():
    """Create api_tokens table if missing and backfill missing columns."""
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            last_used_at DATETIME,
            revoked INTEGER DEFAULT 0
        )''')
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(api_tokens)")
        cols = {row[1] for row in cur.fetchall()}
        if "expires_at" not in cols:
            conn.execute("ALTER TABLE api_tokens ADD COLUMN expires_at DATETIME")
        if "last_used_at" not in cols:
            conn.execute("ALTER TABLE api_tokens ADD COLUMN last_used_at DATETIME")
        if "revoked" not in cols:
            conn.execute("ALTER TABLE api_tokens ADD COLUMN revoked INTEGER DEFAULT 0")
        if "name" not in cols:
            conn.execute("ALTER TABLE api_tokens ADD COLUMN name TEXT")
        if "token_hash" not in cols:
            conn.execute("ALTER TABLE api_tokens ADD COLUMN token_hash TEXT")
        if "user_id" not in cols:
            conn.execute("ALTER TABLE api_tokens ADD COLUMN user_id INTEGER")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)")
        conn.commit()

def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

def _parse_validity_seconds(validity: str) -> int:
    if not validity:
        return 0
    try:
        return parse_duration_generic(validity)
    except Exception:
        return 0

def _default_token_validity():
    return current_app.config.get("API_TOKEN_DEFAULT_VALIDITY", "60d")

def _token_bytes_for_length(length_chars: int) -> int:
    # token_urlsafe returns 4/3 bytes length, so invert roughly
    length_chars = max(24, min(length_chars, 256))
    return math.ceil(length_chars * 3 / 4)

def create_api_token(user_id: int, name: str, validity: str = None, length_chars: int = None):
    """
    Create a new API token: returns (plaintext_token, record_dict).
    Only the hash is stored in DB; caller must show plaintext once.
    """
    ensure_api_tokens_table()
    if length_chars is None:
        length_chars = current_app.config.get("API_TOKEN_LENGTH", 64)
    raw_token = secrets.token_urlsafe(_token_bytes_for_length(length_chars))
    token_hash = _hash_token(raw_token)
    now = datetime.now(timezone.utc)
    expires_at = None
    secs = _parse_validity_seconds(validity) if validity else 0
    if secs:
        expires_at = now + timedelta(seconds=secs)
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO api_tokens (name, token_hash, user_id, created_at, expires_at, revoked)
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            (
                name,
                token_hash,
                user_id,
                now.strftime("%Y-%m-%d %H:%M:%S"),
                expires_at.strftime("%Y-%m-%d %H:%M:%S") if expires_at else None,
            ),
        )
        token_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    try:
        from events import log_user_event
        actor_id = getattr(current_user, "id", user_id)
        actor_username = getattr(current_user, "username", None)
        log_user_event(
            "api_token_create",
            user_id,
            {
                "name": name,
                "token_id": token_id,
                "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S") if expires_at else None,
                "by": actor_id,
                "actor_username": actor_username,
            },
        )
    except Exception:
        pass
    record = {
        "id": token_id,
        "name": name,
        "user_id": user_id,
        "expires_at": expires_at,
    }
    return raw_token, record

def list_api_tokens(user_id: int = None):
    ensure_api_tokens_table()
    db_path = current_app.config["DB_PATH"]
    query = "SELECT id, name, token_hash, user_id, created_at, expires_at, last_used_at, revoked FROM api_tokens"
    params = ()
    if user_id is not None:
        query += " WHERE user_id = ?"
        params = (user_id,)
    query += " ORDER BY created_at DESC"
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
    keys = ["id", "name", "token_hash", "user_id", "created_at", "expires_at", "last_used_at", "revoked"]
    return [dict(zip(keys, row)) for row in rows]

def revoke_api_token(token_id: int, user_id: int = None):
    ensure_api_tokens_table()
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        if user_id is None:
            conn.execute("UPDATE api_tokens SET revoked = 1 WHERE id = ?", (token_id,))
        else:
            conn.execute("UPDATE api_tokens SET revoked = 1 WHERE id = ? AND user_id = ?", (token_id, user_id))
        conn.commit()
    try:
        from events import log_user_event
        actor_id = getattr(current_user, "id", user_id)
        actor_username = getattr(current_user, "username", None)
        target_user = user_id if user_id is not None else getattr(current_user, "id", None)
        log_user_event(
            "api_token_revoke",
            target_user,
            {"token_id": token_id, "by": actor_id, "actor_username": actor_username},
        )
    except Exception:
        pass

def verify_api_token(raw_token: str):
    """
    Validate a presented API token.
    Returns dict with token metadata if valid; otherwise None.
    """
    ensure_api_tokens_table()
    token_hash = _hash_token(raw_token)
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, name, user_id, created_at, expires_at, last_used_at, revoked
            FROM api_tokens
            WHERE token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if not row:
            return None
        token = dict(zip(["id", "name", "user_id", "created_at", "expires_at", "last_used_at", "revoked"], row))
        if token.get("revoked"):
            return None
        expires_at = token.get("expires_at")
        if expires_at:
            try:
                exp_dt = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
                if exp_dt < datetime.utcnow():
                    return None
            except Exception:
                pass
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now_str, token["id"]))
        conn.commit()
    return token

# --- API Tokens UI ---
def _parse_dt_str(dt_str):
    if not dt_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(dt_str, fmt)
        except Exception:
            continue
    return None

def _decorate_tokens(tokens):
    now = datetime.utcnow()
    decorated = []
    for token in tokens:
        expires_dt = _parse_dt_str(token.get("expires_at"))
        created_dt = _parse_dt_str(token.get("created_at"))
        last_used_dt = _parse_dt_str(token.get("last_used_at"))
        expired = expires_dt is not None and expires_dt < now
        status = "Revoked" if token.get("revoked") else ("Expired" if expired else "Active")
        status_class = "badge badge-secondary" if expired else "badge badge-success"
        if token.get("revoked"):
            status_class = "badge badge-danger"
        token["expires_display"] = token.get("expires_at") or ""
        token["created_display"] = token.get("created_at") or ""
        token["last_used_display"] = token.get("last_used_at") or ""
        token["status"] = status
        token["status_class"] = status_class
        token["expired"] = expired
        # short hash for display; full available via data attribute
        if token.get("token_hash"):
            token["token_hash_short"] = token["token_hash"][:12] + "..." if len(token["token_hash"]) > 12 else token["token_hash"]
        else:
            token["token_hash_short"] = ""
        decorated.append(token)
    return decorated

@users_bp.route("/tokens", methods=["GET", "POST"])
@login_required
def api_tokens():
    ensure_api_tokens_table()
    generated_token = None
    generated_name = None
    generated_expires = None
    default_validity = _default_token_validity()
    default_length = current_app.config.get("API_TOKEN_LENGTH", 64)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        validity = request.form.get("validity", "").strip() or default_validity
        length_raw = request.form.get("length", "").strip()
        try:
            length_chars = int(length_raw) if length_raw else default_length
        except Exception:
            length_chars = default_length
        if not name:
            name = f"token-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        try:
            raw_token, record = create_api_token(current_user.id, name, validity, length_chars)
            generated_token = raw_token
            generated_name = name
            if record.get("expires_at"):
                generated_expires = record["expires_at"].strftime("%Y-%m-%d %H:%M:%S")
            flash("API token created. Copy and store it now; it will not be shown again.", "success")
        except Exception as e:
            current_app.logger.error(f"[api_tokens] Failed to create token: {e}")
            flash("Failed to create API token. Please try again.", "error")

    tokens = list_api_tokens() if current_user.is_admin() else list_api_tokens(current_user.id)
    tokens = _decorate_tokens(tokens)
    for t in tokens:
        try:
            t["username"] = get_username_by_id(t.get("user_id"))
        except Exception:
            t["username"] = "Unknown"

    return render_template(
        "api_tokens.html",
        tokens=tokens,
        is_admin=current_user.is_admin(),
        generated_token=generated_token,
        generated_name=generated_name,
        generated_expires=generated_expires,
        default_validity=default_validity,
        default_length=default_length,
    )

@users_bp.route("/tokens/<int:token_id>/delete", methods=["POST"])
@login_required
def delete_api_token(token_id):
    ensure_api_tokens_table()
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT user_id, name FROM api_tokens WHERE id = ?", (token_id,)).fetchone()
        if not row:
            flash("API token not found.", "error")
            return redirect(url_for('users.api_tokens'))
        owner_id, token_name = row
        if (owner_id != current_user.id) and (not current_user.is_admin()):
            flash("You do not have permission to delete this token.", "error")
            return redirect(url_for('users.api_tokens'))
        conn.execute("DELETE FROM api_tokens WHERE id = ?", (token_id,))
        conn.commit()
    flash(f"API token '{token_name}' deleted.", "success")
    try:
        from events import log_user_event
        log_user_event(
            "api_token_delete",
            owner_id,
            {
                "token_id": token_id,
                "name": token_name,
                "owner_id": owner_id,
                "by": current_user.id,
                "actor_username": current_user.username,
            },
        )
    except Exception:
        pass
    return redirect(url_for('users.api_tokens'))


@users_bp.route("/tokens/state")
@login_required
def api_tokens_state():
    """
    Lightweight state endpoint to detect additions/deletions for auto-refresh.
    Returns count and max(id) scoped to current user unless admin.
    """
    ensure_api_tokens_table()
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        if current_user.is_admin():
            row = conn.execute("SELECT COUNT(*) as cnt, IFNULL(MAX(id),0) as max_id FROM api_tokens").fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) as cnt, IFNULL(MAX(id),0) as max_id FROM api_tokens WHERE user_id = ?", (current_user.id,)).fetchone()
    return jsonify({"count": row[0], "max_id": row[1]})

# --- User Events Page ---
@users_bp.route('/events')
@login_required
def user_events():
    from events import get_user_events
    import json
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 20))
    user_id = request.args.get('user_id')
    event_type = request.args.get('event_type')
    events = get_user_events(user_id=user_id, event_type=event_type, page=page, page_size=page_size)
    parsed_events = []
    for row in events:
        details = row["details"] if isinstance(row, dict) else row[4]
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {}
        if not isinstance(details, dict):
            details = {}
        time_str = row["timestamp"] if isinstance(row, dict) else (row[6] if len(row) > 6 else "")
        username = row["username"] if isinstance(row, dict) else (row[2] if len(row) > 2 else "")
        actor_username = row["actor_username"] if isinstance(row, dict) else (row[5] if len(row) > 5 else "")
        event_type = row["event_type"] if isinstance(row, dict) else (row[3] if len(row) > 3 else "")
        parsed_events.append({
            "time": time_str,
            "user": username,
            "actor": actor_username,
            "type": event_type,
            "details": details,
        })
    current_app.logger.trace(f"[user_events] events: {parsed_events}")
    return render_template('user_events.html', events=parsed_events, page=page, page_size=page_size)


# --- Force logout if session missing from user_sessions table ---
@users_bp.before_app_request
def enforce_tracked_session():
    from flask import session as flask_session
    if not current_user.is_authenticated:
        return
    sid = flask_session.get('sid')
    if not sid:
        return

    db_path = current_app.config["DB_PATH"]
    now_str = _now_utc_str()
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT last_activity FROM user_sessions WHERE session_id = ?", (sid,)).fetchone()
    if not row:
        # Only log force_logout if this is NOT due to admin action (i.e., session expired or removed for another reason)
        # If you want to log only admin-initiated force_logout, skip logging here
        logout_user()
        flask_session.pop('sid', None)
        flash('You have been logged out by an administrator.', 'warning')
        return redirect(url_for('users.login'))
    # Idle timeout logic
    last_activity = row[0]
    max_idle_str = current_app.config.get('MAX_IDLE_TIME', '1h')
    try:
        max_idle_seconds = parse_idle_time(max_idle_str)
        if max_idle_seconds is None:
            max_idle_seconds = 3600
    except Exception:
        max_idle_seconds = 3600  # fallback 1h
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    try:
        last_dt = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        last_dt = now
    idle_seconds = (now - last_dt).total_seconds()
    current_app.logger.log(5, f"[IDLE] enforce_tracked_session: sid={sid}")
    current_app.logger.log(5, f"[IDLE] enforce_tracked_session: now_str={now_str}")
    current_app.logger.log(5, f"[IDLE] enforce_tracked_session: last_activity={last_activity}")
    current_app.logger.log(5, f"[IDLE] enforce_tracked_session: max_idle_str={max_idle_str} max_idle_seconds={max_idle_seconds}")
    current_app.logger.log(5, f"[IDLE] enforce_tracked_session: idle_seconds={idle_seconds}")
    if idle_seconds > max_idle_seconds:
        current_app.logger.log(5, f"[IDLE] enforce_tracked_session: FORCED LOGOUT due to idle (sid={sid}, idle_seconds={idle_seconds}, max_idle_seconds={max_idle_seconds})")
        from events import log_user_event
        log_user_event('force_logout', current_user.id, {'username': current_user.username, 'by': current_user.id, 'actor_username': current_user.username})
        logout_user()
        flask_session.pop('sid', None)
        flash('You have been logged out due to inactivity.', 'warning')
        return redirect(url_for('users.login'))
    # Only update last_activity if not idle
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE user_sessions SET last_activity = ? WHERE session_id = ?", (now_str, sid))


# --- User Events API for AJAX polling ---
@users_bp.route('/events/api')
@login_required
def user_events_api():
    from events import get_user_events
    import json
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 20))
    user_id = request.args.get('user_id')
    event_type = request.args.get('event_type')
    events = get_user_events(user_id=user_id, event_type=event_type, page=page, page_size=page_size)
    current_app.logger.debug(f"[AJAX /users/events/api] user_id={user_id} event_type={event_type} events_count={len(events)}")
    parsed_events = []
    for row in events:
        details = row["details"] if isinstance(row, dict) else row[4]
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {}
        if not isinstance(details, dict):
            details = {}
        time_str = row["timestamp"] if isinstance(row, dict) else (row[6] if len(row) > 6 else "")
        username = row["username"] if isinstance(row, dict) else (row[2] if len(row) > 2 else "")
        actor_username = row["actor_username"] if isinstance(row, dict) else (row[5] if len(row) > 5 else "")
        event_type_val = row["event_type"] if isinstance(row, dict) else (row[3] if len(row) > 3 else "")
        parsed_events.append({
            "time": time_str,
            "user": username,
            "actor": actor_username,
            "type": event_type_val,
            "details": details,
        })
    return jsonify({'events': parsed_events})


# --- Test endpoint to verify session DB writes ---
@users_bp.route('/test_session_db')
@login_required
def test_session_db():
    db_path = current_app.config["DB_PATH"]
    try:
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute("SELECT session_id, user_id, login_time, last_activity FROM user_sessions").fetchall()
        return jsonify({"db_path": db_path, "rows": [dict(zip(["session_id", "user_id", "login_time", "last_activity"], row)) for row in rows]})
    except Exception as e:
        return jsonify({"db_path": db_path, "error": str(e)})

def ensure_sessions_table():
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER,
            login_time TEXT,
            last_activity TEXT
        )''')
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(user_sessions)")
        cols = [row[1] for row in cur.fetchall()]
        if "last_activity" not in cols:
            conn.execute("ALTER TABLE user_sessions ADD COLUMN last_activity TEXT")
        conn.execute("""
            UPDATE user_sessions
            SET last_activity = login_time
            WHERE last_activity IS NULL OR last_activity = ''
        """)
        conn.commit()

def get_logged_in_user_ids():
    ensure_sessions_table()
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT DISTINCT user_id FROM user_sessions").fetchall()
        return set(row[0] for row in rows)

def get_user_idle_map():
    ensure_sessions_table()
    db_path = current_app.config["DB_PATH"]
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    idle = {}
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("""
            SELECT user_id, MAX(COALESCE(last_activity, login_time)) AS last_ts
            FROM user_sessions
            GROUP BY user_id
        """).fetchall()
    for user_id, last_ts in rows:
        try:
            parsed = datetime.strptime(last_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            continue
        delta = now - parsed
        if delta.total_seconds() < 0:
            continue
        minutes = int(delta.total_seconds() // 60)
        hours = minutes // 60
        minutes = minutes % 60
        idle[user_id] = f"{hours:02d}:{minutes:02d}"
    return idle

def get_auth_source_for_username(username):
    key = (username or "").lower()
    if not key:
        return "local"
    # Add logic for LDAP/local detection if needed
    return "local"


# --- Approve User (Admin Only) ---
@users_bp.route('/approve_user/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
    from user_models import get_user_by_id
    user = get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users.manage_users'))
    if user.status != 'pending':
        flash('User is not pending approval.', 'info')
        return redirect(url_for('users.manage_users'))
    import sqlite3
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    # Log user event
    try:
        from events import log_user_event
        log_user_event('approve', user_id, {'by': current_user.id, 'username': user.username, 'actor_username': current_user.username})
    except Exception:
        pass
    flash('User approved and activated.', 'success')
    return redirect(url_for('users.manage_users'))
# --- Toggle User Active (Admin Only) ---
@users_bp.route('/toggle_active/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_active(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
    from user_models import get_user_by_id
    user = get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users.manage_users'))
    # Toggle between 'active' and 'deactivated'
    import sqlite3
    new_status = 'deactivated' if user.status == 'active' else 'active'
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    # Log user event
    try:
        from events import log_user_event
        log_user_event('suspend' if new_status == 'deactivated' else 'activate', user_id, {'by': current_user.id, 'username': user.username, 'actor_username': current_user.username})
    except Exception:
        pass
    flash(f'User {"activated" if new_status == "active" else "deactivated"}.', 'success')
    return redirect(url_for('users.manage_users'))



@users_bp.route('/change_role/<int:user_id>', methods=['POST'])
@login_required
def change_role(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
    new_role = request.form.get('role')
    if new_role not in ('user', 'admin'):
        flash('Invalid role.', 'error')
        return redirect(url_for('users.manage_users'))
    from user_models import update_user_role
    update_user_role(user_id, new_role)
    # Log user event
    try:
        from events import log_user_event
        log_user_event('change_role', user_id, {'by': current_user.id, 'role': new_role, 'username': get_username_by_id(user_id), 'actor_username': current_user.username})
    except Exception:
        pass
    flash('User role updated.', 'success')
    return redirect(url_for('users.manage_users'))

@users_bp.route('/manage')
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
        # user['auth_source'] is already set from DB in get_all_users()
        user['idle'] = idle_map.get(user['id'], '') if user['is_logged_in'] else ''
    return render_template('manage_users.html', users=users)

# --- Admin Reset Password ---
@users_bp.route('/reset_password/<int:user_id>', methods=['POST'])
@login_required
def reset_password(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
    from user_models import get_user_by_id
    user = get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users.manage_users'))
    if user.auth_source == 'ldap':
        flash('Cannot reset password for LDAP users. Passwords are managed by your LDAP/Active Directory administrator.', 'warning')
        return redirect(url_for('users.manage_users'))
    # Generate a new random password
    new_password = secrets.token_urlsafe(10)
    from werkzeug.security import generate_password_hash
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), user_id))
    # Log user event
    try:
        from events import log_user_event
        log_user_event('reset_password', user_id, {'by': current_user.id, 'username': user.username, 'actor_username': current_user.username})
    except Exception:
        pass
    flash(f"Password for user '{user.username}' has been reset. New password: {new_password}", 'success')
    return redirect(url_for('users.manage_users'))

@users_bp.route('/api')
@login_required
def api_users():
    if not current_user.is_admin():
        return jsonify({'error': 'forbidden'}), 403
    users = get_all_users()
    logged_in_ids = get_logged_in_user_ids()
    idle_map = get_user_idle_map()
    user_list = []
    for user in users:
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

@users_bp.route('/admin_logout/<int:user_id>', methods=['POST'])
@login_required
def admin_logout(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
    db_path = current_app.config["DB_PATH"]
    from user_models import get_username_by_id
    target_username = get_username_by_id(user_id)
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
    from events import log_user_event
    log_user_event('force_logout', user_id, {
        'username': target_username,
        'by': current_user.id,
        'actor_username': current_user.username
    })
    if user_id == current_user.id:
        logout_user()
        flash('You have been logged out.', 'success')
        return redirect(url_for('users.login'))
    else:
        flash('User has been logged out from all sessions.', 'success')
        return redirect(url_for('users.manage_users'))

@users_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
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
            # Log only to user_events, not main events
            try:
                from events import log_user_event
                log_user_event('add', user_id, {'by': current_user.id, 'role': role, 'email': email, 'username': username, 'actor_username': current_user.username})
            except Exception as e:
                pass
            flash('User added successfully.', 'success')
            return redirect(url_for('users.manage_users'))
        else:
            flash('Failed to add user.', 'error')
    return render_template('add_user.html')

@users_bp.route('/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('users.manage_users'))
    from user_models import get_username_by_id
    username = get_username_by_id(user_id)
    # Log only to user_events, not main events
    try:
        from events import log_user_event
        log_user_event('delete', user_id, {'by': current_user.id, 'username': username, 'actor_username': current_user.username})
    except Exception as e:
        pass
    # Actually delete user from DB
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    flash('User deleted.', 'success')
    return redirect(url_for('users.manage_users'))

@users_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    # Enforce allow_self_registration from config.ini
    allow_self_registration = current_app.config.get('allow_self_registration', True)
    # If config value is a string, normalize to bool
    if isinstance(allow_self_registration, str):
        allow_self_registration = allow_self_registration.lower() == 'true'
    if not allow_self_registration:
        flash('Self-registration is disabled by administrator.', 'error')
        return redirect(url_for('users.login'))
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
            from user_models import get_user_by_username, create_user_db
            existing_user = get_user_by_username(username)
            if existing_user:
                errors.append("Username already exists.")
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("register.html")
        # Check if this is the first user (make them admin)
        conn = sqlite3.connect(current_app.config["DB_PATH"])
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
            current_app.logger.info(f"New user registered: {username} with role: {role}")
            return redirect(url_for('users.login'))
        else:
            flash("Registration failed. Please try again.", "error")
            return render_template("register.html")
    return render_template("register.html")

@users_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")
        from user_models import get_user_by_username, create_user_db, update_last_login
        user = get_user_by_username(username)
        if user:
            current_app.logger.warning(f"[DEBUG LOGIN] user={user.username} role={user.role} status={user.status} auth_source={getattr(user, 'auth_source', None)}")
            pw_ok = user.check_password(password)
            current_app.logger.warning(f"[DEBUG LOGIN] check_password={pw_ok}")
            if user.status == 'deactivated':
                flash("User account is suspended. Contact administrator.", "error")
                current_app.logger.warning(f"Login attempt for suspended user: {username}")
            elif user.status == 'pending':
                flash("User account is pending approval by administrator.", "error")
                current_app.logger.warning(f"Login attempt for pending user: {username}")
            elif user.status == 'active' and getattr(user, 'auth_source', 'local') == 'ldap':
                from ldap_utils import ldap_authenticate
                ldap_result = ldap_authenticate(username, password, current_app.config, current_app.logger)
                if ldap_result:
                    login_user(user)
                    update_last_login(user.id)
                    from events import log_user_event
                    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
                    log_user_event('login', user.id, {'username': user.username, 'by': user.id, 'actor_username': user.username, 'ip': ip_addr})
                    current_app.logger.info(f"User {username} authenticated via LDAP and synced to local DB.")
                    return redirect(url_for('index'))
                else:
                    flash("Invalid username or password.", "error")
                    current_app.logger.warning(f"Failed login attempt for: {username} (LDAP)")
            elif user.status == 'active' and pw_ok:
                login_user(user)
                update_last_login(user.id)
                from events import log_user_event
                ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
                log_user_event('login', user.id, {'username': user.username, 'by': user.id, 'actor_username': user.username, 'ip': ip_addr})
                current_app.logger.info(f"User {username} logged in from IP {ip_addr}")
                return redirect(url_for('index'))
            else:
                flash("Invalid username or password.", "error")
                current_app.logger.warning(f"Failed login attempt for: {username}")
        else:
            from ldap_utils import ldap_authenticate
            ldap_result = ldap_authenticate(username, password, current_app.config, current_app.logger)
            if ldap_result:
                user_id = create_user_db(username, password, role='user', email=ldap_result.get('email'), status='active', auth_source='ldap')
                # You may want to update LDAP_IMPORTED_USERS and LDAP_SOURCE_CACHE here
                user = get_user_by_username(username)
                if user and user.status == 'active':
                    login_user(user)
                    update_last_login(user.id)
                    from events import log_user_event
                    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
                    log_user_event('login', user.id, {'username': user.username, 'by': user.id, 'actor_username': user.username, 'ip': ip_addr})
                    current_app.logger.info(f"User {username} authenticated via LDAP and synced to local DB.")
                    return redirect(url_for('index'))
                else:
                    flash("LDAP authentication succeeded but local user could not be activated. Contact administrator.", "error")
                    current_app.logger.error(f"LDAP auth ok for {username} but local user creation/activation failed.")
            else:
                flash("Invalid username or password.", "error")
                current_app.logger.warning(f"Failed login attempt for: {username} (local + LDAP)")
    return render_template("login.html")

@users_bp.route('/logout')
@login_required
def logout():
    current_app.logger.info(f"User {current_user.username} logged out")
    from events import log_user_event
    log_user_event('logout', current_user.id, {'username': current_user.username, 'by': current_user.id, 'actor_username': current_user.username})
    logout_user()
    flask_session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('users.login'))

# --- Idle Timeout Parsing Helper ---
    # ...existing code...

# Add more user management routes as needed
