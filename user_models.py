
import sqlite3
import json
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from flask import current_app

def set_user_active(user_id, active: bool):
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if active else 0, user_id))
    conn.commit()
    conn.close()

class User(UserMixin):
    def __init__(self, id, username, password_hash, role, email=None, created_at=None, last_login=None, status='pending', auth_source='local', custom_columns=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.email = email
        self.created_at = created_at
        self.last_login = last_login
        self.status = status  # 'pending', 'active', 'disabled'
        self.auth_source = auth_source  # 'local' or 'ldap'
        self.custom_columns = custom_columns or {}

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        # Flask-Login uses this property to determine if the user is active
        return self.status == 'active'

    def is_admin(self):
        return self.role == 'admin'

    @staticmethod
    def create_user(username, password, role='user', email=None):
        password_hash = generate_password_hash(password)
        return User(None, username, password_hash, role, email, status='pending')


def ensure_auth_source_column(conn):
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in cur.fetchall()]
    if "auth_source" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN auth_source TEXT DEFAULT 'local'")
        conn.commit()

def _parse_custom_columns(raw_value):
    if not raw_value:
        return {}
    try:
        data = json.loads(raw_value)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def get_user_by_id(user_id):
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    ensure_auth_source_column(conn)
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        if 'status' in row.keys():
            status = row['status']
        elif 'is_active' in row.keys():
            status = 'active' if row['is_active'] else 'disabled'
        else:
            status = 'active'
        return User(
            id=row['id'],
            username=row['username'],
            password_hash=row['password_hash'],
            role=row['role'],
            email=row['email'],
            created_at=row['created_at'],
            last_login=row['last_login'],
            status=status,
            auth_source=row['auth_source'] if 'auth_source' in row.keys() else 'local',
            custom_columns=_parse_custom_columns(row['custom_columns']) if 'custom_columns' in row.keys() else {}
        )
    return None

def get_user_by_username(username):
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    ensure_auth_source_column(conn)
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if row:
        return User(
            id=row['id'],
            username=row['username'],
            password_hash=row['password_hash'],
            role=row['role'],
            email=row['email'],
            created_at=row['created_at'],
            last_login=row['last_login'],
            status=row['status'] if 'status' in row.keys() else ('active' if row.get('is_active', 1) else 'disabled'),
            auth_source=row['auth_source'] if 'auth_source' in row.keys() else 'local',
            custom_columns=_parse_custom_columns(row['custom_columns']) if 'custom_columns' in row.keys() else {}
        )
    return None

def get_all_users():
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    ensure_auth_source_column(conn)
    cur.execute("SELECT * FROM users ORDER BY username")
    rows = cur.fetchall()
    conn.close()
    users = []
    for row in rows:
        if 'status' in row.keys():
            status = row['status']
        elif 'is_active' in row.keys():
            status = 'active' if row['is_active'] else 'disabled'
        else:
            status = 'active'
        users.append({
            'id': row['id'],
            'username': row['username'],
            'role': row['role'],
            'email': row['email'],
            'created_at': row['created_at'],
            'last_login': row['last_login'],
            'status': status,
            'auth_source': row['auth_source'] if 'auth_source' in row.keys() else 'local',
            'custom_columns': _parse_custom_columns(row['custom_columns']) if 'custom_columns' in row.keys() else {}
        })
    return users

def create_user_db(username, password, role='user', email=None, status='pending', auth_source='local'):
    if auth_source == 'ldap':
        password_hash = ''
    else:
        password_hash = generate_password_hash(password)
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    try:
        ensure_auth_source_column(conn)
        cur.execute(
            "INSERT INTO users (username, password_hash, role, email, status, auth_source) VALUES (?, ?, ?, ?, ?, ?)",
            (username, password_hash, role, email, status, auth_source)
        )
        conn.commit()
        user_id = cur.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def update_user_role(user_id, new_role):
    if new_role not in ('user', 'admin'):
        return False
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    return True

def delete_user_db(user_id):
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def update_last_login(user_id):
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET last_login = ? WHERE id = ?",
        (datetime.now(timezone.utc), user_id)
    )
    conn.commit()
    conn.close()

def get_username_by_id(user_id):
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else "Unknown"

def get_user_theme_style(user_id):
    try:
        conn = sqlite3.connect(current_app.config["DB_PATH"])
        cur = conn.cursor()
        cur.execute("SELECT custom_columns FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        conn.close()
    except sqlite3.OperationalError:
        return "modern"
    data = _parse_custom_columns(row[0]) if row else {}
    theme = data.get("theme_style", "modern")
    return theme if theme in ("modern", "classic") else "modern"

def get_user_theme_color(user_id):
    try:
        conn = sqlite3.connect(current_app.config["DB_PATH"])
        cur = conn.cursor()
        cur.execute("SELECT custom_columns FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        conn.close()
    except sqlite3.OperationalError:
        return "snow"
    data = _parse_custom_columns(row[0]) if row else {}
    color = data.get("theme_color", "snow")
    return color if color in ("snow", "midnight") else "snow"

def set_user_theme_style(user_id, theme_style):
    theme = theme_style if theme_style in ("modern", "classic") else "modern"
    try:
        conn = sqlite3.connect(current_app.config["DB_PATH"])
        cur = conn.cursor()
        cur.execute("SELECT custom_columns FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        data = _parse_custom_columns(row[0]) if row else {}
        data["theme_style"] = theme
        cur.execute(
            "UPDATE users SET custom_columns = ? WHERE id = ?",
            (json.dumps(data, separators=(",", ":")), user_id),
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.OperationalError:
        return False

def set_user_theme_color(user_id, theme_color):
    color = theme_color if theme_color in ("snow", "midnight") else "snow"
    try:
        conn = sqlite3.connect(current_app.config["DB_PATH"])
        cur = conn.cursor()
        cur.execute("SELECT custom_columns FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        data = _parse_custom_columns(row[0]) if row else {}
        data["theme_color"] = color
        cur.execute(
            "UPDATE users SET custom_columns = ? WHERE id = ?",
            (json.dumps(data, separators=(",", ":")), user_id),
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.OperationalError:
        return False
