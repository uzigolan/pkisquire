import hashlib
import math
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user

from user_models import get_username_by_id


def parse_duration_generic(s):
    if not s:
        raise ValueError("Empty duration")
    s = s.strip().lower()
    import re

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


def ensure_api_tokens_table():
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            last_used_at DATETIME,
            revoked INTEGER DEFAULT 0
        )"""
        )
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
    length_chars = max(24, min(length_chars, 256))
    return math.ceil(length_chars * 3 / 4)


def create_api_token(user_id: int, name: str, validity: str = None, length_chars: int = None):
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
    record = {"id": token_id, "name": name, "user_id": user_id, "expires_at": expires_at}
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


def verify_api_token(raw_token: str):
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
        if token.get("token_hash"):
            token["token_hash_short"] = token["token_hash"][:12] + "..." if len(token["token_hash"]) > 12 else token["token_hash"]
        else:
            token["token_hash_short"] = ""
        decorated.append(token)
    return decorated


def api_tokens_page():
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


def delete_api_token(token_id):
    ensure_api_tokens_table()
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT user_id, name FROM api_tokens WHERE id = ?", (token_id,)).fetchone()
        if not row:
            flash("API token not found.", "error")
            return redirect(url_for("users.api_tokens"))
        owner_id, token_name = row
        if (owner_id != current_user.id) and (not current_user.is_admin()):
            flash("You do not have permission to delete this token.", "error")
            return redirect(url_for("users.api_tokens"))
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
    return redirect(url_for("users.api_tokens"))


def api_tokens_state():
    ensure_api_tokens_table()
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        if current_user.is_admin():
            row = conn.execute("SELECT COUNT(*) as cnt, IFNULL(MAX(id),0) as max_id FROM api_tokens").fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) as cnt, IFNULL(MAX(id),0) as max_id FROM api_tokens WHERE user_id = ?",
                (current_user.id,),
            ).fetchone()
    return jsonify({"count": row[0], "max_id": row[1]})
