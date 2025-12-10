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

    # User Events table
    cur.execute('''CREATE TABLE IF NOT EXISTS user_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        event_type TEXT,
        actor_id INTEGER,
        actor_username TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        details TEXT
    )''')

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

    # Challenge Passwords table
    cur.execute('''CREATE TABLE IF NOT EXISTS challenge_passwords (
        value TEXT PRIMARY KEY,
        user_id INTEGER,
        created_at TEXT,
        validity TEXT,
        consumed INTEGER DEFAULT 0
    )''')

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
        status TEXT,
        auth_source TEXT DEFAULT 'local'
    )''')

    # Certificates table
    cur.execute('''CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY,
        subject TEXT,
        serial TEXT,
        cert_pem TEXT,
        issued_via TEXT CHECK(issued_via IN ('ui','scep','est','manual','unknown')) DEFAULT 'unknown',
        revoked INTEGER DEFAULT 0,
        user_id INTEGER
    )''')

    # Events table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_name TEXT,
        user_id TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        details TEXT
    )
    ''')

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

    # RA policies table
    cur.execute('''CREATE TABLE IF NOT EXISTS ra_policies (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT CHECK(type IN ("system", "user")) NOT NULL,
        user_id INTEGER,
        ext_config TEXT,
        restrictions TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        validity_period TEXT DEFAULT '365',
        is_est_default INTEGER DEFAULT 0,
        is_scep_default INTEGER DEFAULT 0
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

    # Seed RA policies from extension configs in pki-misc
    misc_dir = os.path.join(basedir, "pki-misc")
    existing_policies = {row[0] for row in cur.execute("SELECT name FROM ra_policies")}
    seeded_count = 0
    for filename in sorted(os.listdir(misc_dir)):
        if not filename.lower().endswith(".cnf") or "ext" not in filename.lower():
            continue
        policy_name = filename
        user_id = None
        if filename.startswith("server_ext_") and filename.lower().endswith(".cnf"):
            suffix = filename[len("server_ext_"):-4]
            try:
                user_id = int(suffix)
            except Exception:
                user_id = None
        if policy_name in existing_policies:
            continue
        filepath = os.path.join(misc_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                ext_config = f.read()
        except Exception as e:
            print(f"[init_db] Warning: Could not read {filename}: {e}")
            continue

        cur.execute(
            """
            INSERT INTO ra_policies (name, type, user_id, ext_config, restrictions, validity_period)
            VALUES (?, ?, ?, ?, '', '365')
            """,
            (policy_name, 'system' if user_id is None else 'user', user_id, ext_config),
        )
        seeded_count += 1

    if seeded_count:
        print(f"[init_db] Seeded {seeded_count} RA policy config(s) from pki-misc")

    # Ensure a default system policy exists
    def ensure_default_system_policy():
        cur.execute("SELECT id FROM ra_policies WHERE type='system' ORDER BY id LIMIT 1")
        existing_sys = cur.fetchone()
        if existing_sys:
            cur.execute("UPDATE ra_policies SET type='user' WHERE type='system' AND id != ?", (existing_sys[0],))
            return
        # Try to load server_ext.cnf as the default system policy
        server_ext_path = os.path.join(basedir, "pki-misc", "server_ext.cnf")
        ext_config = ""
        if os.path.exists(server_ext_path):
            with open(server_ext_path, "r", encoding="utf-8") as f:
                ext_config = f.read()
        cur.execute(
            """
            INSERT INTO ra_policies (name, type, user_id, ext_config, restrictions, validity_period, is_est_default, is_scep_default)
            VALUES (?, 'system', NULL, ?, '', '365', 1, 1)
            """,
            ("system_default", ext_config),
        )
        print("[init_db] Default system signing policy created (system_default)")

    ensure_default_system_policy()
    conn.commit()
    conn.close()
    print("[init_db] Database initialized.")

if __name__ == "__main__":
    main()
