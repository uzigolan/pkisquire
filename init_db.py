import os
import sqlite3
from datetime import datetime

def main():
    # Load DB path from config.ini
    import configparser
    basedir = os.path.abspath(os.path.dirname(__file__))
    config_path = os.path.join(basedir, "config.ini")
    cfg = configparser.ConfigParser()
    cfg.read(config_path)
    db_path = os.path.join(basedir, cfg.get("PATHS", "db_path"))

    print(f"[init_db] Using DB: {db_path}")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()


    # Users table
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password_hash TEXT,
        role TEXT,
        email TEXT,
        created_at TEXT,
        last_login TEXT,
        status TEXT
    )''')

    # Certificates table
    cur.execute('''CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY,
        subject TEXT,
        serial TEXT,
        cert_pem TEXT,
        revoked INTEGER DEFAULT 0,
        user_id INTEGER
    )''')

    # Profiles table
    cur.execute('''CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER NOT NULL,
        filename VARCHAR(255) NOT NULL,
        template_name VARCHAR(255) NOT NULL,
        profile_type VARCHAR(255),
        user_id INTEGER,
        PRIMARY KEY (id),
        UNIQUE (filename)
    )''')

    # Keys table
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

    # CSRs table
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

    # User sessions table
    cur.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
        session_id TEXT PRIMARY KEY,
        user_id INTEGER,
        login_time TEXT
    )''')


    # Create default admin user if not exists
    cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not cur.fetchone():
        from werkzeug.security import generate_password_hash
        password_hash = generate_password_hash("pikachu")
        cur.execute(
            "INSERT INTO users (username, password_hash, role, email, status) VALUES (?, ?, ?, ?, ?)",
            ("admin", password_hash, "admin", "admin@localhost", "active")
        )
        print("[init_db] Default admin user created: admin / pikachu")
    else:
        print("[init_db] Admin user already exists.")
    conn.commit()
    conn.close()
    print("[init_db] Database initialized.")

if __name__ == "__main__":
    main()
