# User Management Implementation Instructions

## Overview
Implement a user authentication and management system for Pikachu CA with two user roles: **User** and **Admin**, with **multi-tenancy support** where each resource is owned by a specific user.

---

## Features to Implement

### 1. User Types
- **User**: Access only to their own certificates, CSRs, keys, and profiles
- **Admin**: Full access to ALL users' resources + user management capabilities

### 2. Resource Ownership (Multi-Tenancy)
- Each certificate is associated with a specific user
- Each CSR is associated with a specific user
- Each key is associated with a specific user
- Each profile is associated with a specific user
- Users can only view/manage their own resources
- Admins can view/manage all resources from all users

### 3. Admin Capabilities
- View list of all users
- Delete users (and optionally their resources)
- Change user roles (promote User to Admin, demote Admin to User)
- View and manage all users' resources
- See "User" column in all resource lists

### 4. Registration System
- Public registration page with validation
- Username requirements: 3-20 characters, alphanumeric + underscore
- Password requirements: Minimum 6 characters, must match confirmation
- Email: Optional field with format validation
- Real-time client-side validation with error messages
- Submit button disabled until all fields are valid
- First registered user becomes admin (optional)

### 5. Authentication System
- Login page with username/password
- Session-based authentication
- All routes require login (registration is public)
- Protected routes requiring login
- Admin-only routes for user management
- Resource filtering based on user ownership

---

## Implementation Steps

### Step 1: Database Schema

#### A. Create Users Table

Create a new `users` table in the SQLite database (`db/certs.db`):

```sql
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

-- Create default admin user (password: admin123 - CHANGE IN PRODUCTION!)
-- Password hash for 'admin123' using werkzeug security
INSERT INTO users (username, password_hash, role, email) 
VALUES ('admin', 'pbkdf2:sha256:600000$salt$hash', 'admin', 'admin@example.com');
```

#### B. Add user_id Column to Existing Tables

Add `user_id` foreign key to all resource tables:

```sql
-- Add user_id to certificates table
ALTER TABLE certificates ADD COLUMN user_id INTEGER REFERENCES users(id);

-- Add user_id to keys table (if exists)
ALTER TABLE keys ADD COLUMN user_id INTEGER REFERENCES users(id);

-- Add user_id to requests table (CSRs)
ALTER TABLE requests ADD COLUMN user_id INTEGER REFERENCES users(id);

-- Add user_id to profiles table
ALTER TABLE profiles ADD COLUMN user_id INTEGER REFERENCES users(id);

-- For migration: Assign existing resources to admin user
UPDATE certificates SET user_id = 1 WHERE user_id IS NULL;
UPDATE keys SET user_id = 1 WHERE user_id IS NULL;
UPDATE requests SET user_id = 1 WHERE user_id IS NULL;
UPDATE profiles SET user_id = 1 WHERE user_id IS NULL;

-- Make user_id NOT NULL after migration (optional but recommended)
-- Note: This requires recreating tables in SQLite, or enforce in application logic
```

#### C. Create Indexes for Performance

```sql
-- Create indexes on user_id columns for faster queries
CREATE INDEX IF NOT EXISTS idx_certificates_user_id ON certificates(user_id);
CREATE INDEX IF NOT EXISTS idx_keys_user_id ON keys(user_id);
CREATE INDEX IF NOT EXISTS idx_requests_user_id ON requests(user_id);
CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON profiles(user_id);
```

### Step 2: User Model

Add to `models.py` or create `user_models.py`:

```python
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(UserMixin):
    def __init__(self, id, username, password_hash, role, email=None, 
                 created_at=None, last_login=None, is_active=True):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.email = email
        self.created_at = created_at
        self.last_login = last_login
        self.is_active = is_active
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        """Check if user has admin role"""
        return self.role == 'admin'
    
    @staticmethod
    def create_user(username, password, role='user', email=None):
        """Create new user with hashed password"""
        password_hash = generate_password_hash(password)
        return User(None, username, password_hash, role, email)
```

### Step 3: User Management Functions

Add database helper functions:

```python
def get_user_by_id(user_id):
    """Retrieve user by ID"""
    conn = sqlite3.connect(app.config["DB_PATH"])
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
            is_active=row['is_active']
        )
    return None

def get_user_by_username(username):
    """Retrieve user by username"""
    conn = sqlite3.connect(app.config["DB_PATH"])
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
            is_active=row['is_active']
        )
    return None

def get_all_users():
    """Retrieve all users"""
    conn = sqlite3.connect(app.config["DB_PATH"])
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
    """Create new user in database"""
    from werkzeug.security import generate_password_hash
    
    password_hash = generate_password_hash(password)
    conn = sqlite3.connect(app.config["DB_PATH"])
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
        return None  # Username already exists
    finally:
        conn.close()

def update_user_role(user_id, new_role):
    """Update last login timestamp"""
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET last_login = ? WHERE id = ?",
        (datetime.now(timezone.utc), user_id)
    )
    conn.commit()
    conn.close()

def get_username_by_id(user_id):
    """Get username by user ID"""
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else "Unknown"
```     )
        conn.commit()
        user_id = cur.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        return None  # Username already exists
    finally:
        conn.close()

def update_user_role(user_id, new_role):
    """Update user role"""
    if new_role not in ('user', 'admin'):
        return False
    
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    return True

def delete_user_db(user_id):
    """Delete user from database"""
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def update_last_login(user_id):
    """Update last login timestamp"""
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET last_login = ? WHERE id = ?",
        (datetime.now(timezone.utc), user_id)
    )
    conn.commit()
    conn.close()
```

### Step 4: Flask-Login Setup

Update `app.py` to add Flask-Login:

```python
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import re  # Add for regex validation

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(int(user_id))
```

### Step 5: Registration and Authentication Routes

Add registration, login, and logout routes to `app.py`:

#### A. Registration Route

```python
@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration page - public access"""
    # If already logged in, redirect to index
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        password_confirm = request.form.get("password_confirm", "").strip()
        email = request.form.get("email", "").strip()
        
        # Server-side validation (redundant with client-side, but necessary for security)
        errors = []
        
        # Validate username
        if not username:
            errors.append("Username is required.")
        elif len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        elif len(username) > 20:
            errors.append("Username must not exceed 20 characters.")
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append("Username can only contain letters, numbers, and underscores.")
        
        # Validate password
        if not password:
            errors.append("Password is required.")
        elif len(password) < 6:
            errors.append("Password must be at least 6 characters.")
        
        # Validate password confirmation
        if password != password_confirm:
            errors.append("Passwords do not match.")
        
        # Validate email (optional, but if provided must be valid)
        if email:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                errors.append("Invalid email format.")
        
        # Check if username already exists
        if not errors:
            existing_user = get_user_by_username(username)
            if existing_user:
                errors.append("Username already exists.")
        
        # If validation fails, show errors
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("register.html")
        
        # Check if this is the first user (make them admin)
        conn = sqlite3.connect(app.config["DB_PATH"])
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        user_count = cur.fetchone()[0]
        conn.close()
        
        role = 'admin' if user_count == 0 else 'user'
        
        # Create user
        user_id = create_user_db(username, password, role, email or None)
        
        if user_id:
            flash(f"Account created successfully! You can now log in.{' You are the first user and have been granted admin privileges.' if role == 'admin' else ''}", "success")
            app.logger.info(f"New user registered: {username} with role: {role}")
            return redirect(url_for('login'))
        else:
            flash("Registration failed. Please try again.", "error")
            return render_template("register.html")
    
    return render_template("register.html")
```

#### B. Login Route

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    """User login page"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")
        
        user = get_user_by_username(username)
        
        if user and user.check_password(password) and user.is_active:
            login_user(user)
            update_last_login(user.id)
            
            # Redirect to next page or index
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password.", "error")
            app.logger.warning(f"Failed login attempt for username: {username}")
    
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    """User logout"""
    app.logger.info(f"User {current_user.username} logged out")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))
```

### Step 6: Admin-Only Routes

Add user management routes:

```python
from functools import wraps

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('login'))
        if not current_user.is_admin():
            flash("Admin access required.", "error")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/admin/users")
@admin_required
def manage_users():
    """Admin page to view and manage users"""
    users = get_all_users()
    return render_template("manage_users.html", users=users)

@app.route("/admin/users/create", methods=["POST"])
@admin_required
def create_user():
    """Admin creates a new user"""
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "user").strip()
    email = request.form.get("email", "").strip()
    
    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for('manage_users'))
    
    if role not in ('user', 'admin'):
        role = 'user'
    
    user_id = create_user_db(username, password, role, email or None)
    
    if user_id:
        flash(f"User '{username}' created successfully.", "success")
        app.logger.info(f"Admin {current_user.username} created user: {username} with role: {role}")
    else:
        flash(f"Failed to create user. Username '{username}' may already exist.", "error")
    
    return redirect(url_for('manage_users'))

@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def change_user_role(user_id):
    """Admin changes user role"""
    new_role = request.form.get("role", "").strip()
    
    if new_role not in ('user', 'admin'):
        flash("Invalid role specified.", "error")
        return redirect(url_for('manage_users'))
    
    # Prevent admin from demoting themselves
    if user_id == current_user.id:
        flash("You cannot change your own role.", "error")
        return redirect(url_for('manage_users'))
    
    user = get_user_by_id(user_id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('manage_users'))
    
    if update_user_role(user_id, new_role):
        flash(f"User '{user.username}' role changed to '{new_role}'.", "success")
        app.logger.info(f"Admin {current_user.username} changed {user.username} role to {new_role}")
    else:
        flash("Failed to update user role.", "error")
    
    return redirect(url_for('manage_users'))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    """Admin deletes a user"""
    # Prevent admin from deleting themselves
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('manage_users'))
    
    user = get_user_by_id(user_id)
    if not user:
        flash("User not found.", "error")
### Step 7: Update Resource Query Functions

Modify all database query functions to filter by user:

#### A. Certificate Queries

```python
def get_certificates_for_user(user_id=None, is_admin=False):
    """Get certificates filtered by user ownership"""
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    if is_admin:
        # Admin sees all certificates with user information
        cur.execute("""
            SELECT c.*, u.username 
            FROM certificates c
            LEFT JOIN users u ON c.user_id = u.id
            ORDER BY c.id DESC
        """)
    else:
        # Regular user sees only their certificates
        cur.execute("""
### Step 10: Update HTML Templates to Show User Column and Filter Dropdowns

#### Important: Dropdown Filtering
All pages with key/profile selection dropdowns must filter options by user ownership:
- **CSR Generation page** (`generate_csr.html`) - Filter key and profile dropdowns
- **Sign/Submit page** (`sign.html`) - Filter key and profile dropdowns
- **Any page with resource selection** - Apply user filtering

Users see only their own resources in dropdowns. Admins see all resources with username labels.

#### Update `sign.html` - Filter Dropdowns

```html
<form method="POST" action="{{ url_for('submit') }}">
    <div class="mb-3">
        <label for="key_id" class="form-label">Select Key</label>
        <select class="form-select" id="key_id" name="key_id" required>
            <option value="">-- Choose a key --</option>
            {% for key in keys %}
            <option value="{{ key.id }}">
                {{ key.name }} ({{ key.key_type }})
                {% if is_admin and key.username %}
                    - [{{ key.username }}]
                {% endif %}
            </option>
            {% endfor %}
        </select>
        {% if not keys %}
        <small class="text-muted">No keys available. <a href="{{ url_for('x509_keys.generate_key') }}">Generate a key</a></small>
        {% endif %}
    </div>
    
    <div class="mb-3">
        <label for="profile_id" class="form-label">Select Profile</label>
        <select class="form-select" id="profile_id" name="profile_id" required>
            <option value="">-- Choose a profile --</option>
            {% for profile in profiles %}
            <option value="{{ profile.id }}">
                {{ profile.name }}
                {% if is_admin and profile.username %}
                    - [{{ profile.username }}]
                {% endif %}
            </option>
            {% endfor %}
        </select>
        {% if not profiles %}
        <small class="text-muted">No profiles available. <a href="{{ url_for('x509_profiles.create_profile') }}">Create a profile</a></small>
        {% endif %}
    </div>
    
    <div class="mb-3">
        <label for="csr" class="form-label">CSR (PEM format)</label>
        <textarea class="form-control" id="csr" name="csr" rows="10" required></textarea>
    </div>
    
    <button type="submit" class="btn btn-primary">Submit & Sign</button>
</form>
```

#### Update `generate_csr.html` - Filter Dropdowns

```html
<form method="POST" action="{{ url_for('x509_requests.create_request') }}">
    <div class="mb-3">
        <label for="key_id" class="form-label">Select Key</label>
        <select class="form-select" id="key_id" name="key_id" required>
            <option value="">-- Choose a key --</option>
            {% for key in keys %}
            <option value="{{ key.id }}">
                {{ key.name }} ({{ key.key_type }})
                {% if is_admin and key.username %}
                    - [{{ key.username }}]
                {% endif %}
            </option>
            {% endfor %}
        </select>
        {% if not keys %}
        <small class="text-muted">No keys available. <a href="{{ url_for('x509_keys.generate_key') }}">Generate a key first</a></small>
        {% endif %}
    </div>
    
    <div class="mb-3">
        <label for="profile_id" class="form-label">Select Profile</label>
        <select class="form-select" id="profile_id" name="profile_id" required>
            <option value="">-- Choose a profile --</option>
            {% for profile in profiles %}
            <option value="{{ profile.id }}">
                {{ profile.name }}
                {% if is_admin and profile.username %}
                    - [{{ profile.username }}]
                {% endif %}
            </option>
            {% endfor %}
        </select>
        {% if not profiles %}
        <small class="text-muted">No profiles available. <a href="{{ url_for('x509_profiles.create_profile') }}">Create a profile first</a></small>
        {% endif %}
    </div>
    
    <div class="mb-3">
        <label for="common_name" class="form-label">Common Name (CN)</label>
        <input type="text" class="form-control" id="common_name" name="common_name" required>
    </div>
    
    <!-- Additional CSR fields... -->
    
    <button type="submit" class="btn btn-primary">Generate CSR</button>
</form>
```

#### Update `list_certificates.html`

Add "User" column to certificate list:

```html
<table class="table table-striped">
    <thead>
        <tr>
            <th>ID</th>
            <th>Serial</th>
            <th>Subject</th>
            <th>Issued</th>
            <th>Expires</th>
            <th>Status</th>
            {% if is_admin %}
            <th>User</th>  <!-- Add this column for admin -->
            {% endif %}
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        {% for cert in certificates %}
        <tr>
            <td>{{ cert.id }}</td>
            <td>{{ cert.serial }}</td>
            <td>{{ cert.subject }}</td>
            <td>{{ cert.issued_at }}</td>
            <td>{{ cert.expires_at }}</td>
            <td>
                {% if cert.status == 'active' %}
                    <span class="badge bg-success">Active</span>
                {% elif cert.status == 'revoked' %}
                    <span class="badge bg-danger">Revoked</span>
                {% else %}
                    <span class="badge bg-secondary">{{ cert.status }}</span>
                {% endif %}
            </td>
            {% if is_admin %}
            <td>
                <span class="badge bg-info">{{ cert.username }}</span>
            </td>
            {% endif %}
            <td>
                <a href="{{ url_for('view_certificate', cert_id=cert.id) }}" class="btn btn-sm btn-primary">View</a>
                <!-- other actions -->
            </td>
        </tr>
        {% endfor %}
    </tbody>
</table>
```

#### Update `list_keys.html`

Add "User" column:

```html
<table class="table table-striped">
    <thead>
        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Type</th>
            <th>Created</th>
            {% if is_admin %}
            <th>User</th>
            {% endif %}
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        {% for key in keys %}
        <tr>
            <td>{{ key.id }}</td>
            <td>{{ key.name }}</td>
            <td>{{ key.key_type }}</td>
            <td>{{ key.created_at }}</td>
            {% if is_admin %}
            <td><span class="badge bg-info">{{ key.username }}</span></td>
            {% endif %}
            <td>
                <a href="{{ url_for('x509_keys.view_key', key_id=key.id) }}" class="btn btn-sm btn-primary">View</a>
            </td>
        </tr>
        {% endfor %}
    </tbody>
</table>
```

#### Update `list_csrs.html`

Add "User" column:

```html
<table class="table table-striped">
    <thead>
        <tr>
            <th>ID</th>
            <th>Subject</th>
            <th>Created</th>
            <th>Status</th>
            {% if is_admin %}
            <th>User</th>
            {% endif %}
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        {% for req in requests %}
        <tr>
            <td>{{ req.id }}</td>
            <td>{{ req.subject }}</td>
            <td>{{ req.created_at }}</td>
            <td>{{ req.status }}</td>
            {% if is_admin %}
            <td><span class="badge bg-info">{{ req.username }}</span></td>
            {% endif %}
            <td>
                <a href="{{ url_for('x509_requests.view_request', req_id=req.id) }}" class="btn btn-sm btn-primary">View</a>
            </td>
        </tr>
        {% endfor %}
    </tbody>
</table>
```

#### Update `list_profiles.html`

Add "User" column:

```html
<table class="table table-striped">
    <thead>
        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Description</th>
            <th>Created</th>
            {% if is_admin %}
            <th>User</th>
            {% endif %}
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        {% for profile in profiles %}
        <tr>
            <td>{{ profile.id }}</td>
            <td>{{ profile.name }}</td>
            <td>{{ profile.description }}</td>
            <td>{{ profile.created_at }}</td>
            {% if is_admin %}
            <td><span class="badge bg-info">{{ profile.username }}</span></td>
            {% endif %}
            <td>
                <a href="{{ url_for('x509_profiles.view_profile', profile_id=profile.id) }}" class="btn btn-sm btn-primary">View</a>
            </td>
        </tr>
        {% endfor %}
    </tbody>
</table>
```

### Step 11: HTML Templates for Authentication

#### `login.html`JOIN users u ON c.user_id = u.id
### Step 12: Handle User Deletion with Cascade Options

When deleting a user, decide how to handle their resources:

```python
@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    """Admin deletes a user"""
    # Prevent admin from deleting themselves
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('manage_users'))
    
    user = get_user_by_id(user_id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('manage_users'))
    
    # Get cascade option from form
    cascade_option = request.form.get("cascade", "keep").strip()
    
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    
    if cascade_option == "delete":
        # Delete all user's resources
        cur.execute("DELETE FROM certificates WHERE user_id = ?", (user_id,))
        cur.execute("DELETE FROM keys WHERE user_id = ?", (user_id,))
        cur.execute("DELETE FROM requests WHERE user_id = ?", (user_id,))
        cur.execute("DELETE FROM profiles WHERE user_id = ?", (user_id,))
        app.logger.info(f"Admin {current_user.username} deleted user {user.username} with all resources")
    elif cascade_option == "reassign":
        # Reassign resources to admin
        cur.execute("UPDATE certificates SET user_id = ? WHERE user_id = ?", (current_user.id, user_id))
        cur.execute("UPDATE keys SET user_id = ? WHERE user_id = ?", (current_user.id, user_id))
        cur.execute("UPDATE requests SET user_id = ? WHERE user_id = ?", (current_user.id, user_id))
        cur.execute("UPDATE profiles SET user_id = ? WHERE user_id = ?", (current_user.id, user_id))
        app.logger.info(f"Admin {current_user.username} deleted user {user.username} and reassigned resources")
    else:
        # Keep resources orphaned (user_id remains but user is deleted)
        app.logger.info(f"Admin {current_user.username} deleted user {user.username}, resources kept")
    
    # Delete the user
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    flash(f"User '{user.username}' deleted successfully.", "success")
    return redirect(url_for('manage_users'))
```

Update the delete user button in `manage_users.html`:

```html
<!-- Delete User Form with Cascade Options -->
<form method="POST" action="{{ url_for('delete_user', user_id=user.id) }}" style="display:inline;">
    <select name="cascade" class="form-select form-select-sm d-inline-block w-auto">
        <option value="keep">Keep resources</option>
        <option value="reassign">Reassign to me</option>
        <option value="delete">Delete all resources</option>
    </select>
    <button type="submit" class="btn btn-sm btn-danger" 
            onclick="return confirm('Are you sure you want to delete user {{ user.username }}?');">
        Delete User
    </button>
</form>
```

### Step 13: Database Initialization
            ORDER BY c.id DESC
        """, (user_id,))
    
    certs = cur.fetchall()
    conn.close()
    return certs

def get_certificate_by_id(cert_id, user_id=None, is_admin=False):
    """Get single certificate with ownership check"""
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    if is_admin:
        cur.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,))
    else:
        cur.execute(
            "SELECT * FROM certificates WHERE id = ? AND user_id = ?",
            (cert_id, user_id)
        )
    
    cert = cur.fetchone()
    conn.close()
    return cert
```

## Testing Checklist

### Registration Tests
- [ ] Register page is publicly accessible
- [ ] Username validation: minimum 3 characters
- [ ] Username validation: maximum 20 characters
- [ ] Username validation: alphanumeric + underscore only
- [ ] Username validation: required field
- [ ] Email validation: optional field (can be empty)
- [ ] Email validation: format check when provided
- [ ] Password validation: minimum 6 characters
- [ ] Password validation: required field
- [ ] Password confirmation: matches password
- [ ] Password confirmation: required field
- [ ] Submit button disabled when validation fails
- [ ] Submit button enabled when all fields valid
- [ ] Real-time error messages display for each field
- [ ] Error messages clear when field becomes valid
- [ ] Server-side validation matches client-side
- [ ] Username uniqueness check (no duplicates)
- [ ] First registered user becomes admin
- [ ] Second registered user becomes regular user
- [ ] Successful registration redirects to login
- [ ] Already logged-in users redirected from register page

### Authentication Tests
- [ ] Login with correct credentials
- [ ] Login with incorrect credentials (should fail)
- [ ] Logout functionality
- [ ] Protected routes require login
- [ ] Session persists across requests
- [ ] Password is hashed in database (never plaintext)
- [ ] Login page has link to register page
- [ ] Cannot access features without registration

### User Management Tests
- [ ] Admin can view user list
- [ ] Admin can create new user
- [ ] Admin can change user role (user → admin)
- [ ] Admin can change user role (admin → user)
- [ ] Admin can delete user
- [ ] Admin can delete user with cascade options
- [ ] Admin cannot delete themselves
- [ ] Admin cannot change their own role
## Logging

All user management and resource access actions should be logged:

```python
# Registration
app.logger.info(f"New user registered: {username} with role: {role}")
app.logger.warning(f"Registration failed for username: {username} (already exists)")
app.logger.warning(f"Registration validation failed: {errors}")

# Authentication
app.logger.info(f"User {username} logged in")
app.logger.warning(f"Failed login attempt for: {username}")
app.logger.info(f"User {username} logged out")

# User Management
app.logger.info(f"Admin {admin_user} created user: {new_user} with role: {role}")
app.logger.info(f"Admin {admin_user} changed {user} role to {role}")
app.logger.info(f"Admin {admin_user} deleted user: {user}")
## Migration Path

### Phase 1: User Registration and Authentication Setup
1. Install Flask-Login and werkzeug
2. Create database migration to add users table
3. Add user model and helper functions
4. Set up Flask-Login in app.py
5. Create registration route with validation
6. Create login/logout routes
7. Create register.html template with client-side validation
8. Create login.html template
9. Test registration validation (all rules)
10. Test first user becomes admin
11. Test login/logout functionality

### Phase 2: User Management
8. Create admin routes for user management
9. Create manage_users.html template
10. Test user CRUD operations
11. Test role management

### Phase 3: Multi-Tenancy Implementation
12. Add user_id column to all resource tables (certificates, keys, requests, profiles)
13. Create database indexes on user_id columns
14. Migrate existing resources to admin user (user_id = 1)
15. Update all query functions to filter by user
16. Add ownership checks to all routes
17. Update blueprints (x509_keys, x509_profiles, x509_requests)

### Phase 4: UI Updates
18. Update all list templates to show "User" column for admins
19. Pass is_admin flag to all templates
20. Test that user column displays correctly
21. Test that non-admin users don't see user column

### Phase 5: Testing & Deployment
22. Run comprehensive test checklist
23. Test resource isolation between users
24. Test admin access to all resources
25. Test access denial scenarios
26. Review logs for proper audit trail
27. Update documentation
28. Deploy to productionr {username} attempted to access admin panel (access denied)")
``` ] Admin can see all users' certificates
- [ ] Admin can see all users' keys
- [ ] Admin can see all users' CSRs
- [ ] Admin can see all users' profiles
- [ ] "User" column displays correctly in all lists (admin view)
- [ ] "User" column is hidden for non-admin users
- [ ] New certificates are associated with current user
- [ ] New keys are associated with current user
- [ ] New CSRs are associated with current user
- [ ] New profiles are associated with current user
- [ ] Migrated resources are assigned to admin user
    else:
        cur.execute("""
            SELECT k.*, u.username 
            FROM keys k
            LEFT JOIN users u ON k.user_id = u.id
            WHERE k.user_id = ?
            ORDER BY k.id DESC
        """, (user_id,))
    
    keys = cur.fetchall()
    conn.close()
    return keys

def get_key_by_id(key_id, user_id=None, is_admin=False):
    """Get single key with ownership check"""
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    if is_admin:
        cur.execute("SELECT * FROM keys WHERE id = ?", (key_id,))
    else:
        cur.execute(
            "SELECT * FROM keys WHERE id = ? AND user_id = ?",
            (key_id, user_id)
        )
    
    key = cur.fetchone()
    conn.close()
    return key
```

#### C. CSR Queries

```python
def get_requests_for_user(user_id=None, is_admin=False):
    """Get CSRs filtered by user ownership"""
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    if is_admin:
        cur.execute("""
            SELECT r.*, u.username 
            FROM requests r
            LEFT JOIN users u ON r.user_id = u.id
            ORDER BY r.id DESC
        """)
    else:
        cur.execute("""
            SELECT r.*, u.username 
            FROM requests r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.user_id = ?
            ORDER BY r.id DESC
        """, (user_id,))
    
    requests = cur.fetchall()
    conn.close()
    return requests

def get_request_by_id(request_id, user_id=None, is_admin=False):
    """Get single CSR with ownership check"""
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    if is_admin:
        cur.execute("SELECT * FROM requests WHERE id = ?", (request_id,))
    else:
        cur.execute(
            "SELECT * FROM requests WHERE id = ? AND user_id = ?",
            (request_id, user_id)
        )
    
    request = cur.fetchone()
    conn.close()
    return request
```

#### D. Profile Queries

```python
def get_profiles_for_user(user_id=None, is_admin=False):
    """Get profiles filtered by user ownership"""
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    if is_admin:
        cur.execute("""
#### B. Submit Certificate Route

```python
@app.route("/submit", methods=["POST"])
@login_required
def submit():
    """Submit CSR - associate with current user and validate ownership of key/profile"""
    csr_pem = request.form.get("csr", "").strip()
    key_id = request.form.get("key_id")
    profile_id = request.form.get("profile_id")
    
    # Security check: Verify user owns the selected key
    if key_id:
        key = get_key_by_id(key_id, current_user.id, current_user.is_admin())
        if not key:
            flash("Selected key not found or access denied.", "error")
            return redirect(url_for('sign'))
    
    # Security check: Verify user owns the selected profile
    if profile_id:
        profile = get_profile_by_id(profile_id, current_user.id, current_user.is_admin())
        if not profile:
            flash("Selected profile not found or access denied.", "error")
            return redirect(url_for('sign'))
    
    # Validate CSR...
    try:
        csr_obj = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
    except Exception as e:
        flash(f"Invalid CSR: {str(e)}", "error")
        return redirect(url_for('sign'))
    
    # Sign certificate...
    # cert_pem = sign_certificate(csr_obj, profile, ...)
    
    # Save certificate with user_id
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO certificates (cert_pem, serial, issued_at, expires_at, user_id, key_id, profile_id, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (cert_pem, serial, issued_at, expires_at, current_user.id, key_id, profile_id, 'active')
    )
    conn.commit()
    conn.close()
    
    flash("Certificate signed successfully!", "success")
    app.logger.info(f"User {current_user.username} submitted and signed certificate {serial}")
    return redirect(url_for('index'))
```     cur.execute("SELECT * FROM profiles WHERE id = ?", (profile_id,))
    else:
        cur.execute(
            "SELECT * FROM profiles WHERE id = ? AND user_id = ?",
            (profile_id, user_id)
        )
    
    profile = cur.fetchone()
    conn.close()
    return profile
```

### Step 8: Update Route Handlers

Modify existing routes to include user ownership and filtering:

#### A. List Certificates Route

```python
@app.route("/")
@app.route("/certs")
@login_required
def index():
    """List certificates - filtered by user"""
    certs = get_certificates_for_user(
        user_id=current_user.id,
        is_admin=current_user.is_admin()
    )
    
    # Process certificates as before...
    cert_list = []
    for row in certs:
        # existing certificate processing code...
        cert_dict['username'] = row['username'] if 'username' in row.keys() else 'Unknown'
        cert_list.append(cert_dict)
    
    return render_template("list_certificates.html", 
                         certificates=cert_list,
                         is_admin=current_user.is_admin())

@app.route("/sign")
@login_required
def sign():
    """Sign page - show only user's keys and profiles in dropdowns"""
    # Get keys filtered by user - user sees only their keys, admin sees all
    keys = get_keys_for_user(
        user_id=current_user.id,
        is_admin=current_user.is_admin()
    )
    
    # Get profiles filtered by user - user sees only their profiles, admin sees all
    profiles = get_profiles_for_user(
        user_id=current_user.id,
        is_admin=current_user.is_admin()
    )
    
    return render_template("sign.html", 
                         keys=keys, 
                         profiles=profiles,
                         is_admin=current_user.is_admin())

@app.route("/generate_csr", methods=["GET"])
@login_required
def generate_csr_page():
    """Generate CSR page - show only user's keys and profiles in dropdowns"""
    # Get keys filtered by user - user sees only their keys, admin sees all
    keys = get_keys_for_user(
        user_id=current_user.id,
        is_admin=current_user.is_admin()
    )
    
    # Get profiles filtered by user - user sees only their profiles, admin sees all
    profiles = get_profiles_for_user(
        user_id=current_user.id,
        is_admin=current_user.is_admin()
    )
    
    return render_template("generate_csr.html", 
                         keys=keys, 
                         profiles=profiles,
                         is_admin=current_user.is_admin())
```

#### B. Submit Certificate Route

```python
@app.route("/submit", methods=["POST"])
@login_required
def submit():
    """Submit CSR - associate with current user"""
    csr_pem = request.form.get("csr", "").strip()
    
    # Validate CSR...
    # Sign certificate...
    
    # Save certificate with user_id
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO certificates (cert_pem, serial, issued_at, expires_at, user_id, status) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (cert_pem, serial, issued_at, expires_at, current_user.id, 'active')
    )
    conn.commit()
    conn.close()
    
    flash("Certificate signed successfully!", "success")
    return redirect(url_for('index'))
```

#### C. View/Delete/Revoke with Ownership Check

```python
@app.route("/view/<int:cert_id>")
@login_required
def view_certificate(cert_id):
    """View certificate details - with ownership check"""
    cert = get_certificate_by_id(
        cert_id,
        user_id=current_user.id,
        is_admin=current_user.is_admin()
    )
    
    if not cert:
        flash("Certificate not found or access denied.", "error")
        return redirect(url_for('index'))
    
    # Show certificate details...
    return render_template("view.html", certificate=cert)

@app.route("/delete/<int:cert_id>", methods=["POST"])
@login_required
def delete_certificate(cert_id):
    """Delete certificate - with ownership check"""
    secret = request.form.get("delete_secret", "").strip()
    expected = str(app.config.get("DELETE_SECRET", "")).strip()
    
    if secret != expected:
        flash("Invalid delete secret.", "error")
        return redirect(url_for('index'))
    
    # Check ownership
    cert = get_certificate_by_id(
        cert_id,
        user_id=current_user.id,
        is_admin=current_user.is_admin()
    )
    
    if not cert:
        flash("Certificate not found or access denied.", "error")
        return redirect(url_for('index'))
    
    # Delete certificate
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
    conn.commit()
    conn.close()
    
    app.logger.info(f"User {current_user.username} deleted certificate {cert_id}")
    flash("Certificate deleted.", "success")
    return redirect(url_for('index'))

@app.route("/revoke/<int:cert_id>", methods=["POST"])
@login_required
def revoke(cert_id):
    """Revoke certificate - with ownership check"""
    secret = request.form.get("delete_secret", "").strip()
    expected = str(app.config.get("DELETE_SECRET", "")).strip()
    
    if secret != expected:
        flash("Invalid secret.", "error")
        return redirect(url_for('index'))
    
    # Check ownership
    cert = get_certificate_by_id(
        cert_id,
        user_id=current_user.id,
        is_admin=current_user.is_admin()
    )
    
    if not cert:
        flash("Certificate not found or access denied.", "error")
        return redirect(url_for('index'))
    
    # Revoke certificate...
    # Update database and CRL...
    
    app.logger.info(f"User {current_user.username} revoked certificate {cert_id}")
    flash("Certificate revoked.", "success")
    return redirect(url_for('index'))
```

### Step 9: Update Blueprint Routes (x509_keys, x509_profiles, x509_requests)

Apply the same user filtering pattern to all blueprint routes:

#### x509_keys Blueprint

```python
# In x509_keys.py

@x509_keys_bp.route("/keys")
@login_required
def list_keys():
    """List keys for current user"""
    keys = get_keys_for_user(
        user_id=current_user.id,
        is_admin=current_user.is_admin()
    )
    return render_template("list_keys.html", 
                         keys=keys, 
                         is_admin=current_user.is_admin())

@x509_keys_bp.route("/keys/view/<int:key_id>")
@login_required
def view_key(key_id):
    """View key - with ownership check"""
    key = get_key_by_id(key_id, current_user.id, current_user.is_admin())
    if not key:
        flash("Key not found or access denied.", "error")
        return redirect(url_for('x509_keys.list_keys'))
    
    return render_template("view_key.html", key=key)

@x509_keys_bp.route("/keys/generate", methods=["POST"])
@login_required
def generate_key():
    """Generate key - associate with current user"""
    # Generate key...
    
    # Save with user_id
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO keys (name, key_type, key_pem, user_id) VALUES (?, ?, ?, ?)",
        (key_name, key_type, key_pem, current_user.id)
    )
    conn.commit()
    conn.close()
    
    return redirect(url_for('x509_keys.list_keys'))

@x509_keys_bp.route("/keys/<int:key_id>/delete", methods=["POST"])
@login_required
def delete_key(key_id):
    """Delete key - with ownership check"""
    key = get_key_by_id(key_id, current_user.id, current_user.is_admin())
    if not key:
#### x509_profiles Blueprint

```python
# In x509_profiles.py

@x509_profiles_bp.route("/profiles")
@login_required
def list_profiles():
    """List profiles for current user"""
    profiles = get_profiles_for_user(
        user_id=current_user.id,
        is_admin=current_user.is_admin()
    )
    return render_template("list_profiles.html", 
                         profiles=profiles, 
                         is_admin=current_user.is_admin())

@x509_profiles_bp.route("/profiles/view/<int:profile_id>")
@login_required
def view_profile(profile_id):
    """View profile - with ownership check"""
    profile = get_profile_by_id(profile_id, current_user.id, current_user.is_admin())
    if not profile:
        flash("Profile not found or access denied.", "error")
        return redirect(url_for('x509_profiles.list_profiles'))
    
    return render_template("view_profile.html", profile=profile)

```python
# In x509_profiles.py

@x509_profiles_bp.route("/profiles")
@login_required
def list_profiles():
    """List profiles for current user"""
    profiles = get_profiles_for_user(
        user_id=current_user.id,
        is_admin=current_user.is_admin()
    )
    return render_template("list_profiles.html", profiles=profiles, is_admin=current_user.is_admin())

@x509_profiles_bp.route("/profiles/create", methods=["POST"])
@login_required
def create_profile():
    """Create profile - associate with current user"""
    # Create profile...
    
#### x509_requests Blueprint

```python
# In x509_requests.py

@x509_requests_bp.route("/requests")
@login_required
def list_requests():
    """List CSRs for current user"""
    requests = get_requests_for_user(
        user_id=current_user.id,
        is_admin=current_user.is_admin()
    )
    return render_template("list_csrs.html", 
                         requests=requests, 
                         is_admin=current_user.is_admin())

@x509_requests_bp.route("/requests/view/<int:request_id>")
@login_required
def view_request(request_id):
    """View CSR - with ownership check"""
    request = get_request_by_id(request_id, current_user.id, current_user.is_admin())
    if not request:
        flash("CSR not found or access denied.", "error")
        return redirect(url_for('x509_requests.list_requests'))
    
    return render_template("view_csr.html", request=request)

@x509_requests_bp.route("/requests/create", methods=["GET", "POST"])
@login_required
def create_request():
    """Create CSR page - show only user's keys and profiles in dropdowns"""
    if request.method == "GET":
        # Get keys and profiles filtered by user for dropdown lists
        keys = get_keys_for_user(
            user_id=current_user.id,
            is_admin=current_user.is_admin()
        )
        profiles = get_profiles_for_user(
            user_id=current_user.id,
            is_admin=current_user.is_admin()
        )
        return render_template("generate_csr.html", 
                             keys=keys, 
                             profiles=profiles,
                             is_admin=current_user.is_admin())
    
    # POST - Create CSR and associate with current user
    key_id = request.form.get("key_id")
    profile_id = request.form.get("profile_id")
    
    # Verify user owns the key (security check)
    key = get_key_by_id(key_id, current_user.id, current_user.is_admin())
    if not key:
        flash("Key not found or access denied.", "error")
        return redirect(url_for('x509_requests.create_request'))
    
    # Verify user owns the profile (security check)
    profile = get_profile_by_id(profile_id, current_user.id, current_user.is_admin())
    if not profile:
        flash("Profile not found or access denied.", "error")
        return redirect(url_for('x509_requests.create_request'))
    
    # Generate CSR using the key and profile...
    # csr_pem = generate_csr(key, profile, ...)
    
    # Save CSR with user_id
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO requests (csr_pem, user_id, key_id, profile_id, status) VALUES (?, ?, ?, ?, ?)",
        (csr_pem, current_user.id, key_id, profile_id, 'pending')
    )
    conn.commit()
    conn.close()
    
    flash("CSR created successfully!", "success")
    app.logger.info(f"User {current_user.username} created CSR with key {key_id} and profile {profile_id}")
    return redirect(url_for('x509_requests.list_requests'))
``` # Create CSR...
    
    # Save with user_id
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO requests (csr_pem, user_id) VALUES (?, ?)",
        (csr_pem, current_user.id)
    )
    conn.commit()
    conn.close()
    
    return redirect(url_for('x509_requests.list_requests'))
``` sign():
    # existing code...

@app.route("/submit", methods=["POST"])
@login_required
def submit():
    # existing code...

# Add @login_required to other routes as needed
```

### Step 8: HTML Templates

## Future Enhancements

- Password reset via email
- User profile management
- Audit log viewer for resource access
- Role-based permissions (more granular than user/admin)
- API token authentication for REST endpoints
- OAuth/SAML integration
- User activity monitoring
- Bulk user import/export
- Resource sharing between users
- User groups/organizations
- Quota management per user (max certificates, keys, etc.)
- Resource usage statistics per user
- Export user's resources as ZIP
- Batch operations on user's resourcess="card-header">
                    <h3>🔐 Login to Pikachu CA</h3>
                </div>
                <div class="card-body">
                    <form method="POST" action="{{ url_for('login') }}">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required autofocus>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Login</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
```

#### `manage_users.html`
```html
{% extends "layout.html" %}

{% block content %}
<div class="container mt-4">
    <h2>👥 User Management</h2>
    
    <!-- Create New User Form -->
    <div class="card mb-4">
        <div class="card-header">
            <h4>Create New User</h4>
        </div>
        <div class="card-body">
            <form method="POST" action="{{ url_for('create_user') }}">
                <div class="row">
                    <div class="col-md-3">
                        <input type="text" class="form-control" name="username" placeholder="Username" required>
                    </div>
                    <div class="col-md-3">
                        <input type="password" class="form-control" name="password" placeholder="Password" required>
                    </div>
                    <div class="col-md-2">
                        <input type="email" class="form-control" name="email" placeholder="Email (optional)">
                    </div>
                    <div class="col-md-2">
                        <select class="form-control" name="role">
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    <div class="col-md-2">
                        <button type="submit" class="btn btn-success">Create User</button>
                    </div>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Users List -->
    <div class="card">
        <div class="card-header">
            <h4>All Users</h4>
        </div>
        <div class="card-body">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Email</th>
                        <th>Created At</th>
                        <th>Last Login</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.id }}</td>
                        <td>
                            {{ user.username }}
                            {% if user.id == current_user.id %}
                                <span class="badge bg-info">You</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if user.role == 'admin' %}
                                <span class="badge bg-danger">Admin</span>
                            {% else %}
                                <span class="badge bg-secondary">User</span>
                            {% endif %}
                        </td>
                        <td>{{ user.email or '-' }}</td>
                        <td>{{ user.created_at }}</td>
                        <td>{{ user.last_login or 'Never' }}</td>
                        <td>
                            {% if user.id != current_user.id %}
                                <!-- Change Role Form -->
                                <form method="POST" action="{{ url_for('change_user_role', user_id=user.id) }}" style="display:inline;">
                                    <select name="role" class="form-select form-select-sm d-inline-block w-auto">
                                        <option value="user" {% if user.role == 'user' %}selected{% endif %}>User</option>
                                        <option value="admin" {% if user.role == 'admin' %}selected{% endif %}>Admin</option>
                                    </select>
                                    <button type="submit" class="btn btn-sm btn-warning">Change Role</button>
                                </form>
                                
                                <!-- Delete User Form -->
                                <form method="POST" action="{{ url_for('delete_user', user_id=user.id) }}" style="display:inline;" onsubmit="return confirm('Are you sure you want to delete user {{ user.username }}?');">
                                    <button type="submit" class="btn btn-sm btn-danger">Delete</button>
                                </form>
                            {% else %}
                                <span class="text-muted">-</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endblock %}
```

### Step 9: Update Navigation (layout.html)

Add user info and logout to navigation:

```html
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container-fluid">
        <a class="navbar-brand" href="/">Pikachu CA</a>
        <!-- existing nav items -->
        
        <div class="navbar-nav ms-auto">
            {% if current_user.is_authenticated %}
                <span class="navbar-text me-3">
                    👤 {{ current_user.username }}
                    {% if current_user.is_admin() %}
                        <span class="badge bg-danger">Admin</span>
                    {% endif %}
                </span>
                {% if current_user.is_admin() %}
                    <a class="nav-link" href="{{ url_for('manage_users') }}">👥 Users</a>
                {% endif %}
                <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
            {% endif %}
        </div>
    </div>
</nav>
```

### Step 10: Database Initialization

Add initialization script or function:

```python
def init_users_table():
    """Initialize users table if it doesn't exist"""
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    
    # Create users table
    cur.execute("""
## Summary of Changes

### Database Changes
- **New table**: `users` (id, username, password_hash, role, email, created_at, last_login, is_active)
- **Unique constraint**: Username must be unique
- **Schema updates**: Add `user_id` column to: certificates, keys, requests, profiles
- **Indexes**: Add indexes on user_id columns for performance
- **Migration**: Assign existing resources to first user (admin)
### Code Changes
- **New dependencies**: Flask-Login, werkzeug
- **New functions**: 
  - User management (create, update, delete, get)
  - Resource filtering by user
  - Ownership validation functions
  - Registration with validation
- **Route updates**: Add @login_required and ownership checks to all resource routes
- **Blueprint updates**: Update x509_keys, x509_profiles, x509_requests with user filtering
- **Public routes**: Only /register and /login are accessible without authentication

### UI Changes
- **New templates**: register.html (with client-side validation), login.html, manage_users.html
- **Client-side validation**: Real-time form validation with error messages
### Security Features
- Public registration with validation
- First user automatically becomes admin
- Client-side validation (UX) + server-side validation (security)
- Username: 3-20 characters, alphanumeric + underscore
- Password: Minimum 6 characters, must match confirmation
- Email: Optional, format validated if provided
- Password hashing with werkzeug PBKDF2-SHA256
- Session-based authentication
- All routes require login except /register and /login
- Resource ownership validation
- Admin-only routes with @admin_required decorator
- Comprehensive audit logging
- Prevention of self-deletion/role-change for admins

### Validation Rules
- **Username**: Required, 3-20 chars, [a-zA-Z0-9_], unique
- **Password**: Required, min 6 chars
- **Password Confirm**: Required, must match password
- **Email**: Optional, must be valid email format if provided
- **Submit button**: Disabled until all validations pass
- **Real-time feedback**: Error messages update on input/blur

---

**Implementation Priority**: High  
**Estimated Effort**: 10-14 hours (with registration + multi-tenancy)  
**Testing Required**: Comprehensive (see checklist)  
**Breaking Changes**: Yes - All features now require registration/login  
**Database Migration**: Requiredrequired decorator
- Comprehensive audit logging
- Prevention of self-deletion/role-change for admins

---

**Implementation Priority**: High  
**Estimated Effort**: 8-12 hours (with multi-tenancy)  
**Testing Required**: Comprehensive (see checklist)  
**Breaking Changes**: No (with proper migration)  
**Database Migration**: Required  

---

*Remember: Following Rule 2 from copilot-instructions.md - Never hard-code paths, require DELETE_SECRET for destructive operations, maintain backward compatibility.*
    cur.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if cur.fetchone()[0] == 0:
        # Create default admin user (password: admin123)
        from werkzeug.security import generate_password_hash
        password_hash = generate_password_hash('admin123')
        cur.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
            ('admin', password_hash, 'admin', 'admin@pikachu-ca.local')
        )
        app.logger.info("Default admin user created (username: admin, password: admin123)")
    
    conn.commit()
    conn.close()

# Call during app startup
with app.app_context():
    init_users_table()
```

---

## Installation Requirements

Add to requirements or install:

```bash
pip install Flask-Login werkzeug
```

---

## Configuration Updates

Update `config.ini` if needed:

```ini
[DEFAULT]
# Session timeout in minutes (optional)
session_timeout = 30

# Maximum login attempts (optional)
max_login_attempts = 5
## Security Considerations

1. **First user becomes admin** - The first registered user automatically gets admin privileges
2. **Client-side validation** - Provides immediate feedback but is NOT a security measure
3. **Server-side validation** - Always validates on server (never trust client)
4. **Password requirements** - Minimum 6 characters (consider increasing to 8+)
5. **Username uniqueness** - Enforced at database level with UNIQUE constraint
6. **Password hashing** - Uses werkzeug PBKDF2-SHA256 (never store plaintext)
7. **Email optional** - Users can register without email (consider making it required for password recovery)
8. **Enable HTTPS** for all authentication operations (especially registration/login)
9. **Log all registration attempts** for audit trail
   - Email verification during registration
   - Password reset functionality (requires email)
   - Two-factor authentication (2FA)
   - Account lockout after failed login attempts
   - More complex password requirements (uppercase, lowercase, numbers, symbols)
   - Session timeout
   - CSRF protection (Flask-WTF)
   - Rate limiting for registration/login
   - CAPTCHA to prevent automated registrationy
   - Two-factor authentication (2FA)
   - Account lockout after failed attempts
   - Password complexity requirements
   - Session timeout
   - CSRF protection (Flask-WTF)

---

## Testing Checklist

- [ ] Login with correct credentials
- [ ] Login with incorrect credentials (should fail)
- [ ] Logout functionality
- [ ] Admin can view user list
- [ ] Admin can create new user
- [ ] Admin can change user role (user → admin)
- [ ] Admin can change user role (admin → user)
- [ ] Admin can delete user
- [ ] Admin cannot delete themselves
- [ ] Admin cannot change their own role
- [ ] User cannot access admin pages
- [ ] Protected routes require login
- [ ] Session persists across requests
- [ ] Password is hashed in database (never plaintext)

---

## Logging

All user management actions should be logged:

```python
app.logger.info(f"User {username} logged in")
app.logger.warning(f"Failed login attempt for: {username}")
app.logger.info(f"Admin {admin_user} created user: {new_user}")
app.logger.info(f"Admin {admin_user} changed {user} role to {role}")
app.logger.info(f"Admin {admin_user} deleted user: {user}")
```

---

## Migration Path

1. Install Flask-Login and werkzeug
2. Create database migration to add users table
3. Add user model and helper functions
4. Set up Flask-Login in app.py
5. Create login/logout routes
6. Create admin routes for user management
7. Create HTML templates
8. Protect existing routes with @login_required
9. Test all functionality
10. Update documentation

---

## Future Enhancements

- Password reset via email
- User profile management
- Audit log viewer
- Role-based permissions (more granular than user/admin)
- API token authentication for REST endpoints
- OAuth/SAML integration
- User activity monitoring
- Bulk user import/export

---

## Backward Compatibility

To maintain backward compatibility during transition:

1. Keep existing `DELETE_SECRET` protection for critical operations
2. Make login optional initially (add `login_optional` decorator)
3. Gradually migrate routes to require authentication
4. Provide migration script for existing installations

---

**Implementation Priority**: High  
**Estimated Effort**: 4-6 hours  
**Testing Required**: Yes  
**Breaking Changes**: No (with proper migration)  

---

*Remember: Following Rule 2 from copilot-instructions.md - Never hard-code paths, require DELETE_SECRET for destructive operations, maintain backward compatibility.*
