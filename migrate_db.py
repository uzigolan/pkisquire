import os
import sqlite3
from werkzeug.security import generate_password_hash


def migrate_db():
    """
    In-place schema upgrade for the configured DB:
    - Ensure tables exist.
    - Add missing columns (including auth_source) without dropping data.
    - Ensure default admin user exists.
    """
    import configparser

    basedir = os.path.abspath(os.path.dirname(__file__))
    config_path = os.path.join(basedir, "config.ini")
    cfg = configparser.ConfigParser()
    cfg.read(config_path)
    db_path = os.path.join(basedir, cfg.get("PATHS", "db_path"))
    print(f"[migrate_db] Migrating in-place: {db_path}")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Helpers
    def ensure_column(table, column, coltype):
        cur.execute(f"PRAGMA table_info({table})")
        cols = [row[1] for row in cur.fetchall()]
        if column not in cols:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")

    # Create tables if missing
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password_hash TEXT,
        role TEXT,
        email TEXT,
        created_at TEXT,
        last_login TEXT,
        status TEXT,
        auth_source TEXT DEFAULT 'local'
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY,
        subject TEXT,
        serial TEXT,
        cert_pem TEXT,
        revoked INTEGER DEFAULT 0,
        user_id INTEGER
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER NOT NULL,
        filename VARCHAR(255) NOT NULL,
        template_name VARCHAR(255) NOT NULL,
        profile_type VARCHAR(255),
        user_id INTEGER,
        PRIMARY KEY (id),
        UNIQUE (filename)
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS keys (
        id INTEGER NOT NULL,
        name VARCHAR(255) NOT NULL,
        key_type VARCHAR(10) NOT NULL,
        key_size INTEGER,
        curve_name VARCHAR(50),
        pqc_alg VARCHAR(20),
        private_key TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at DATETIME,
        user_id INTEGER,
        PRIMARY KEY (id)
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS csrs (
        id INTEGER NOT NULL,
        name VARCHAR(255) NOT NULL,
        key_id INTEGER NOT NULL,
        profile_id INTEGER NOT NULL,
        csr_pem TEXT NOT NULL,
        created_at DATETIME,
        user_id INTEGER,
        PRIMARY KEY (id)
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
        session_id TEXT PRIMARY KEY,
        user_id INTEGER,
        login_time TEXT
    )''')

    # Ensure missing columns on existing tables
    ensure_column('users', 'auth_source', "TEXT DEFAULT 'local'")
    ensure_column('certificates', 'user_id', 'INTEGER')
    ensure_column('profiles', 'user_id', 'INTEGER')
    ensure_column('keys', 'user_id', 'INTEGER')
    ensure_column('csrs', 'user_id', 'INTEGER')

    # Ensure default admin
    cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not cur.fetchone():
        password_hash = generate_password_hash("pikachu")
        cur.execute(
            "INSERT INTO users (username, password_hash, role, email, status, auth_source) VALUES (?, ?, ?, ?, ?, ?)",
            ("admin", password_hash, "admin", "admin@localhost", "active", "local")
        )
        print("[migrate_db] Default admin user created: admin / pikachu")
    else:
        print("[migrate_db] Admin user already exists.")

    conn.commit()
    conn.close()
    print("[migrate_db] Migration complete.")


if __name__ == "__main__":
    migrate_db()
