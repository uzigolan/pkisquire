import sqlite3
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from flask import current_app

class User(UserMixin):
    def __init__(self, id, username, password_hash, role, email=None, created_at=None, last_login=None, is_active_db=True):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.email = email
        self.created_at = created_at
        self.last_login = last_login
        self.is_active_db = is_active_db


    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        # Flask-Login uses this property to determine if the user is active
        return bool(self.is_active_db)

    def is_admin(self):
        return self.role == 'admin'

    @staticmethod
    def create_user(username, password, role='user', email=None):
        password_hash = generate_password_hash(password)
        return User(None, username, password_hash, role, email)

def get_user_by_id(user_id):
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
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
            is_active_db=row['is_active']
        )
    return None

def get_user_by_username(username):
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
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
            is_active_db=row['is_active']
        )
    return None

def get_all_users():
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY username")
    rows = cur.fetchall()
    conn.close()
    users = []
    for row in rows:
        users.append({
            'id': row['id'],
            'username': row['username'],
            'role': row['role'],
            'email': row['email'],
            'created_at': row['created_at'],
            'last_login': row['last_login'],
            'is_active': row['is_active']
        })
    return users

def create_user_db(username, password, role='user', email=None):
    password_hash = generate_password_hash(password)
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, email)
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
