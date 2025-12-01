import os
import sqlite3
from werkzeug.security import generate_password_hash

def migrate_db():
    import configparser
    basedir = os.path.abspath(os.path.dirname(__file__))
    config_path = os.path.join(basedir, "config.ini")
    cfg = configparser.ConfigParser()
    cfg.read(config_path)
    old_db_path = os.path.join(basedir, "db", "certs.db")
    new_db_path = os.path.join(basedir, cfg.get("PATHS", "db_path"))
    print(f"[migrate_db] Migrating from {old_db_path} to {new_db_path}")
    if not os.path.exists(old_db_path):
        print(f"[migrate_db] ERROR: {old_db_path} does not exist.")
        return

    # Connect to old and new DBs
    old_conn = sqlite3.connect(old_db_path)
    old_cur = old_conn.cursor()
    new_conn = sqlite3.connect(new_db_path)
    new_cur = new_conn.cursor()

    # --- Create/upgrade tables in new DB ---
    # Users table
    new_cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password_hash TEXT,
        role TEXT,
        email TEXT,
        created_at TEXT,
        last_login TEXT,
        status TEXT
    )''')
    # Add user_id columns if missing
    def ensure_column(table, column, coltype):
        new_cur.execute(f"PRAGMA table_info({table})")
        cols = [row[1] for row in new_cur.fetchall()]
        if column not in cols:
            new_cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
    ensure_column('certificates', 'user_id', 'INTEGER')
    ensure_column('profiles', 'user_id', 'INTEGER')
    ensure_column('keys', 'user_id', 'INTEGER')
    ensure_column('csrs', 'user_id', 'INTEGER')
    # User sessions table
    new_cur.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
        session_id TEXT PRIMARY KEY,
        user_id INTEGER,
        login_time TEXT
    )''')

    # --- Copy data from old DB to new DB ---
    # certificates
    old_cur.execute('SELECT id, subject, serial, cert_pem, revoked FROM certificates')
    for row in old_cur.fetchall():
        new_cur.execute('INSERT OR IGNORE INTO certificates (id, subject, serial, cert_pem, revoked) VALUES (?, ?, ?, ?, ?)', row)
    # profiles
    old_cur.execute('SELECT id, filename, template_name, profile_type FROM profiles')
    for row in old_cur.fetchall():
        new_cur.execute('INSERT OR IGNORE INTO profiles (id, filename, template_name, profile_type) VALUES (?, ?, ?, ?)', row)
    # keys
    old_cur.execute('SELECT id, name, key_type, key_size, curve_name, pqc_alg, private_key, public_key, created_at FROM keys')
    for row in old_cur.fetchall():
        new_cur.execute('INSERT OR IGNORE INTO keys (id, name, key_type, key_size, curve_name, pqc_alg, private_key, public_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', row)
    # csrs
    old_cur.execute('SELECT id, name, key_id, profile_id, csr_pem, created_at FROM csrs')
    for row in old_cur.fetchall():
        new_cur.execute('INSERT OR IGNORE INTO csrs (id, name, key_id, profile_id, csr_pem, created_at) VALUES (?, ?, ?, ?, ?, ?)', row)

    # --- Add default admin user ---
    new_cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not new_cur.fetchone():
        password_hash = generate_password_hash("pikachu")
        new_cur.execute(
            "INSERT INTO users (username, password_hash, role, email, status) VALUES (?, ?, ?, ?, ?)",
            ("admin", password_hash, "admin", "admin@localhost", "active")
        )
        print("[migrate_db] Default admin user created: admin / pikachu")
    else:
        print("[migrate_db] Admin user already exists.")

    new_conn.commit()
    old_conn.close()
    new_conn.close()
    print("[migrate_db] Migration complete.")

if __name__ == "__main__":
    migrate_db()
