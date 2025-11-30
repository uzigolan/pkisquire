-- User Management Migration Script for Pikachu CA
-- Run this in your SQLite database (db/certs.db)

-- 1. Create users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user', 'admin')),
    email TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT 1
);

-- 2. Add user_id to certificates table
ALTER TABLE certificates ADD COLUMN user_id INTEGER REFERENCES users(id);

-- 3. Add user_id to keys table
ALTER TABLE keys ADD COLUMN user_id INTEGER REFERENCES users(id);

-- 4. Add user_id to requests table
ALTER TABLE requests ADD COLUMN user_id INTEGER REFERENCES users(id);

-- 5. Add user_id to profiles table
ALTER TABLE profiles ADD COLUMN user_id INTEGER REFERENCES users(id);

-- 6. Assign existing resources to admin user (id=1)
UPDATE certificates SET user_id = 1 WHERE user_id IS NULL;
UPDATE keys SET user_id = 1 WHERE user_id IS NULL;
UPDATE requests SET user_id = 1 WHERE user_id IS NULL;
UPDATE profiles SET user_id = 1 WHERE user_id IS NULL;

-- 7. Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_certificates_user_id ON certificates(user_id);
CREATE INDEX IF NOT EXISTS idx_keys_user_id ON keys(user_id);
CREATE INDEX IF NOT EXISTS idx_requests_user_id ON requests(user_id);
CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON profiles(user_id);

-- 8. Create default admin user (change password after first login!)
-- Replace the hash below with a real hash for your admin password
INSERT OR IGNORE INTO users (username, password_hash, role, email) VALUES ('admin', 'pbkdf2:sha256:600000$salt$hash', 'admin', 'admin@example.com');
