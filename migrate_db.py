import os
import sqlite3
from werkzeug.security import generate_password_hash


def migrate_db():

    """
    In-place schema upgrade for the configured DB:
    - Ensure tables exist.
    - Add missing columns (including auth_source) without dropping data.
    - Ensure usernames are unique via index (warn if duplicates block it).
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

    # Challenge Passwords table
    cur.execute('''CREATE TABLE IF NOT EXISTS challenge_passwords (
        value TEXT PRIMARY KEY,
        user_id INTEGER,
        created_at TEXT,
        validity TEXT,
        consumed INTEGER DEFAULT 0
    )''')
    # API tokens table (hash-only storage)
    cur.execute('''CREATE TABLE IF NOT EXISTS api_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        last_used_at DATETIME,
        revoked INTEGER DEFAULT 0
    )''')
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)")
    # Ensure validity column exists if table already created
    def column_exists(table, column):
        cur.execute(f"PRAGMA table_info({table})")
        return any(row[1] == column for row in cur.fetchall())

    if not column_exists('challenge_passwords', 'validity'):
        cur.execute("ALTER TABLE challenge_passwords ADD COLUMN validity TEXT")

    # --- USER EVENTS TABLE LOGIC ---
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

    # --- END USER EVENTS TABLE LOGIC ---

    # Helpers
    def ensure_column(table, column, coltype):
        cur.execute(f"PRAGMA table_info({table})")
        cols = [row[1] for row in cur.fetchall()]
        if column not in cols:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")

    # Create tables if missing
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT,
        role TEXT,
        email TEXT,
        created_at TEXT,
        last_login TEXT,
        status TEXT,
        auth_source TEXT DEFAULT 'local',
        custom TEXT DEFAULT '{"theme_style":"classic","theme_color":"snow"}'
    )''')
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

    cur.execute('''CREATE TABLE IF NOT EXISTS ra_policies (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT CHECK(type IN ("system", "user")) NOT NULL,
        user_id INTEGER,
        ext_config TEXT,
        restrictions TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        validity_period TEXT DEFAULT '365'
    )''')

    # Ensure missing columns on existing tables
    ensure_column('user_events', 'actor_id', 'INTEGER')
    ensure_column('user_events', 'actor_username', 'TEXT')
    ensure_column('user_events', 'username', 'TEXT')
    ensure_column('users', 'auth_source', "TEXT DEFAULT 'local'")
    ensure_column('users', 'custom', "TEXT DEFAULT '{\"theme_style\":\"classic\",\"theme_color\":\"snow\"}'")
    ensure_column('certificates', 'user_id', 'INTEGER')
    ensure_column('certificates', 'issued_via', "TEXT CHECK(issued_via IN ('ui','scep','est','manual','unknown')) DEFAULT 'unknown'")
    ensure_column('profiles', 'user_id', 'INTEGER')
    ensure_column('profiles', 'created_at', 'DATETIME')
    ensure_column('profiles', 'content', 'TEXT')
    ensure_column('keys', 'user_id', 'INTEGER')
    ensure_column('csrs', 'user_id', 'INTEGER')
    ensure_column('ra_policies', 'user_id', 'INTEGER')
    ensure_column('ra_policies', 'ext_config', 'TEXT')
    # Ensure last_activity column exists in user_sessions
    ensure_column('user_sessions', 'last_activity', 'TEXT')
    ensure_column('ra_policies', 'restrictions', 'TEXT')
    ensure_column('ra_policies', 'created_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP')
    ensure_column('ra_policies', 'updated_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP')
    ensure_column('ra_policies', 'validity_period', "TEXT DEFAULT '365'")
    ensure_column('ra_policies', 'type', "TEXT CHECK(type IN ('system', 'user'))")
    ensure_column('ra_policies', 'name', 'TEXT')
    ensure_column('ra_policies', 'is_est_default', 'INTEGER DEFAULT 0')
    ensure_column('ra_policies', 'is_scep_default', 'INTEGER DEFAULT 0')
    # Ensure api_tokens columns exist if table pre-dated these
    ensure_column('api_tokens', 'name', 'TEXT')
    ensure_column('api_tokens', 'token_hash', 'TEXT')
    ensure_column('api_tokens', 'user_id', 'INTEGER')
    ensure_column('api_tokens', 'created_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP')
    ensure_column('api_tokens', 'expires_at', 'DATETIME')
    ensure_column('api_tokens', 'last_used_at', 'DATETIME')
    ensure_column('api_tokens', 'revoked', 'INTEGER DEFAULT 0')

    # Ensure unique usernames via index; warn if duplicates prevent creation
    def ensure_unique_usernames(cursor):
        try:
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            print("[migrate_db] Ensured unique index on users.username (idx_users_username).")
        except sqlite3.IntegrityError as e:
            print(f"[migrate_db] Warning: could not create unique index on users.username: {e}")
            cursor.execute("""
                SELECT username, COUNT(*) AS cnt
                FROM users
                GROUP BY username
                HAVING cnt > 1
            """)
            duplicates = cursor.fetchall()
            if duplicates:
                print("[migrate_db] Duplicate usernames present; resolve manually before rerunning migration:")
                for username, cnt in duplicates:
                    print(f"  username='{username}' count={cnt}")

    ensure_unique_usernames(cur)
    # Ensure default custom settings for users
    default_custom_columns = '{"theme_style":"classic","theme_color":"snow"}'
    cur.execute(
        "UPDATE users SET custom = ? WHERE custom IS NULL OR TRIM(custom) = ''",
        (default_custom_columns,),
    )
    # Backfill issuance source where we can infer it
    cur.execute("UPDATE certificates SET issued_via = 'ui' WHERE issued_via IS NULL AND user_id IS NOT NULL")
    cur.execute("UPDATE certificates SET issued_via = 'unknown' WHERE issued_via IS NULL")
    # Unique index to avoid duplicate names per user/type (use IFNULL to group system/null)
    try:
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_ra_policies_type_user_name ON ra_policies(type, IFNULL(user_id, -1), name)")
    except Exception as e:
        print(f"[migrate_db] Warning: could not create ra_policies unique index: {e}")

    # Rename filename to name in profiles table
    cur.execute("PRAGMA table_info(profiles)")
    columns = [row[1] for row in cur.fetchall()]
    if 'filename' in columns and 'name' not in columns:
        print("[migrate_db] Renaming profiles.filename to profiles.name...")
        cur.execute("ALTER TABLE profiles RENAME COLUMN filename TO name")
        print("[migrate_db] Column renamed successfully")

    # Migrate profile files to database
    print("[migrate_db] Migrating profile files to database...")
    cur.execute("SELECT id, name, content FROM profiles")
    profiles = cur.fetchall()
    
    profile_dir = os.path.join(basedir, "x509_profiles")
    
    migrated_count = 0
    for profile_id, name, content in profiles:
        if not content:  # Only migrate if content is NULL
            filepath = os.path.join(profile_dir, name)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        file_content = f.read()
                    cur.execute("UPDATE profiles SET content = ? WHERE id = ?", (file_content, profile_id))
                    migrated_count += 1
                except Exception as e:
                    print(f"[migrate_db] Warning: Could not migrate {name}: {e}")
    
    if migrated_count > 0:
        print(f"[migrate_db] Migrated {migrated_count} profile(s) from filesystem to database")
    else:
        print("[migrate_db] No profiles needed migration")

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

    # Seed tests API token for automated scripts
    tests_api_token = cfg.get("DEFAULT", "tests_api_token", fallback="").strip()
    if tests_api_token:
        import hashlib
        token_hash = hashlib.sha256(tests_api_token.encode("utf-8")).hexdigest()
        cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
        admin_row = cur.fetchone()
        admin_id = admin_row[0] if admin_row else None
        cur.execute("SELECT 1 FROM api_tokens WHERE token_hash = ?", (token_hash,))
        exists = cur.fetchone()
        if admin_id and not exists:
            cur.execute(
                """
                INSERT INTO api_tokens (name, token_hash, user_id, revoked)
                VALUES (?, ?, ?, 0)
                """,
                ("tests_api_token", token_hash, admin_id),
            )
            print("[migrate_db] Seeded tests_api_token for admin user.")
        elif exists:
            print("[migrate_db] tests_api_token already present; skipping insert.")
        else:
            print("[migrate_db] Warning: could not seed tests_api_token (admin user missing?)")

    # Ensure RA policies have sensible defaults
    cur.execute("UPDATE ra_policies SET type = 'system' WHERE type IS NULL")
    cur.execute("UPDATE ra_policies SET validity_period = '365' WHERE validity_period IS NULL")
    cur.execute("UPDATE ra_policies SET restrictions = '' WHERE restrictions IS NULL")

    # Seed RA policies from extension configs in pki-misc
    misc_dir = os.path.join(basedir, "pki-misc")
    existing = {row[0]: row[1] for row in cur.execute("SELECT name, ext_config FROM ra_policies")}
    inserted = 0
    updated = 0
    for filename in sorted(os.listdir(misc_dir)):
        if not filename.lower().endswith(".cnf") or "ext" not in filename.lower():
            continue
        policy_name = filename
        filepath = os.path.join(misc_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                ext_config = f.read()
        except Exception as e:
            print(f"[migrate_db] Warning: Could not read {filename}: {e}")
            continue

        # map server_ext_*.cnf to user policies
        user_id = None
        if filename.startswith("server_ext_") and filename.lower().endswith(".cnf"):
            suffix = filename[len("server_ext_"):-4]
            try:
                user_id = int(suffix)
            except Exception:
                user_id = None

        if policy_name in existing:
            if not existing[policy_name]:
                cur.execute(
                    "UPDATE ra_policies SET ext_config = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                    (ext_config, policy_name),
                )
                updated += 1
            continue

        cur.execute(
            """
            INSERT INTO ra_policies (name, type, user_id, ext_config, restrictions, validity_period)
            VALUES (?, ?, ?, ?, '', '365')
            """,
            (policy_name, 'system' if user_id is None else 'user', user_id, ext_config),
        )
        inserted += 1

    if inserted or updated:
        print(f"[migrate_db] RA policies updated (inserted={inserted}, filled_missing_content={updated})")

    # Ensure default system policy exists
    def ensure_default_system_policy():
        cur.execute("SELECT id FROM ra_policies WHERE type='system' ORDER BY id LIMIT 1")
        existing_sys = cur.fetchone()
        if existing_sys:
            # ensure only one system policy
            cur.execute("UPDATE ra_policies SET type='user' WHERE type='system' AND id != ?", (existing_sys[0],))
            return
        server_ext_path = os.path.join(basedir, "pki-misc", "server_ext.cnf")
        ext_config = ""
        if os.path.exists(server_ext_path):
            try:
                with open(server_ext_path, "r", encoding="utf-8") as f:
                    ext_config = f.read()
            except Exception:
                ext_config = ""
        cur.execute(
            """
            INSERT INTO ra_policies (name, type, user_id, ext_config, restrictions, validity_period, is_est_default, is_scep_default)
            VALUES (?, 'system', NULL, ?, '', '365', 1, 1)
            """,
            ("system_default", ext_config),
        )
        print("[migrate_db] Default system signing policy created (system_default)")

    ensure_default_system_policy()

    conn.commit()
    conn.close()
    print("[migrate_db] Migration complete.")


if __name__ == "__main__":
    migrate_db()
