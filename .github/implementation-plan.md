# User Management Implementation Plan - Code Analysis

## Current Architecture Overview

### Database Structure
**Current Database**: `db/certs.db` (SQLite)
- **Existing tables**:
  - `certificates` - Stores issued certificates (id, subject, serial, cert_pem, revoked)
  - `keys` - Stores generated keys (SQLAlchemy model)
  - `csrs` - Stores certificate signing requests (SQLAlchemy model)
  - `profiles` - Stores X.509 profiles (SQLAlchemy model)

### Application Structure

#### Main Application (`app.py`)
- **Framework**: Flask with SQLAlchemy ORM
- **Database**: Mixed approach - raw SQLite3 for certificates table, SQLAlchemy for others
- **Configuration**: Loaded from `config.ini`
- **Logging**: RotatingFileHandler to `logs/server.log`
- **Session**: Flask sessions with SECRET_KEY
- **Blueprints registered**: x509_profiles, x509_keys, x509_requests, scep

#### Blueprints
1. **x509_keys.py** - Key management
   - Model: `Key` (SQLAlchemy)
   - Routes: `/generate`, `/keys` (list), `/keys/<id>` (view)
   
2. **x509_profiles.py** - Profile management
   - Model: `Profile` (SQLAlchemy)
   - Routes: Profile CRUD operations
   
3. **x509_requests.py** - CSR management
   - Model: `CSR` (SQLAlchemy)
   - Routes: `/requests/generate`, `/requests` (list), `/requests/<id>/download`

#### Current Routes (app.py)
- `/` or `/certs` - List certificates (uses raw sqlite3)
- `/sign` - Sign page with key/profile dropdowns
- `/submit` - Submit CSR for signing (uses raw sqlite3)
- `/delete/<id>` - Delete certificate (requires DELETE_SECRET)
- `/revoke/<id>` - Revoke certificate (requires DELETE_SECRET)
- `/config` - View config (requires DELETE_SECRET, uses session)

---

## Implementation Strategy

### Phase 1: Database Schema Migration

#### Step 1.1: Add Users Table
**File to modify**: `app.py` (in the database initialization section around line 162)

```python
# Current code (line 162):
with sqlite3.connect(app.config["DB_PATH"]) as conn:
    conn.execute('''CREATE TABLE IF NOT EXISTS certificates (
                        id INTEGER PRIMARY KEY,
                        subject TEXT,
                        serial TEXT,
                        cert_pem TEXT,
                        revoked INTEGER DEFAULT 0
                    )''')
```

**Change to**:
```python
with sqlite3.connect(app.config["DB_PATH"]) as conn:
    # Create users table
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL CHECK(role IN ('user', 'admin')),
                        email TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        is_active BOOLEAN DEFAULT 1
                    )''')
    
    # Create certificates table with user_id
    conn.execute('''CREATE TABLE IF NOT EXISTS certificates (
                        id INTEGER PRIMARY KEY,
                        subject TEXT,
                        serial TEXT,
                        cert_pem TEXT,
                        revoked INTEGER DEFAULT 0,
                        user_id INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )''')
    
    # Create indexes
    conn.execute('CREATE INDEX IF NOT EXISTS idx_certificates_user_id ON certificates(user_id)')
```

#### Step 1.2: Modify SQLAlchemy Models
**Files to modify**:

1. **x509_keys.py** - Add user_id to Key model (line ~10-20)
```python
class Key(db.Model):
    __tablename__ = "keys"
    id         = db.Column(db.Integer,   primary_key=True)
    name       = db.Column(db.String(255), nullable=False)
    key_type   = db.Column(db.String(10),  nullable=False)
    key_size   = db.Column(db.Integer,     nullable=True)
    curve_name = db.Column(db.String(50),  nullable=True)
    pqc_alg    = db.Column(db.String(20),  nullable=True)
    private_key= db.Column(db.Text,        nullable=False)
    public_key = db.Column(db.Text,        nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id    = db.Column(db.Integer, nullable=True)  # ADD THIS LINE
```

2. **x509_profiles.py** - Add user_id to Profile model (line ~10)
```python
class Profile(db.Model):
    __tablename__ = "profiles"
    id            = db.Column(db.Integer, primary_key=True)
    filename      = db.Column(db.String(255), unique=True, nullable=False)
    template_name = db.Column(db.String(255), nullable=False)
    profile_type  = db.Column(db.String(255), nullable=True)
    user_id       = db.Column(db.Integer, nullable=True)  # ADD THIS LINE
```

3. **x509_requests.py** - Add user_id to CSR model (line ~14)
```python
class CSR(db.Model):
    __tablename__ = "csrs"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    key_id = db.Column(db.Integer, nullable=False)
    profile_id = db.Column(db.Integer, nullable=False)
    csr_pem = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=True)  # ADD THIS LINE
```

---

### Phase 2: User Authentication System

#### Step 2.1: Install Dependencies
**Command to run**:
```bash
pip install Flask-Login werkzeug
```

#### Step 2.2: Create User Model and Helper Functions
**File to create**: `user_models.py` (new file in root directory)

**Location**: Create new file alongside `app.py`

**Content**: Complete User model class and all helper functions (get_user_by_id, get_user_by_username, create_user_db, etc.)

#### Step 2.3: Modify app.py - Add Flask-Login
**File to modify**: `app.py`

**Location**: After line 23 (after flask imports)
```python
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
```

**Location**: After line 106 (after db.init_app(app))
```python
# Initialize Flask-Login
from user_models import User, get_user_by_id
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(int(user_id))
```

#### Step 2.4: Add Authentication Routes
**File to modify**: `app.py`

**Location**: After line 500 (before the existing `/` route)

**Add these routes**:
- `/register` - Registration with validation
- `/login` - Login page
- `/logout` - Logout handler

---

### Phase 3: Protect Existing Routes

#### Step 3.1: Add @login_required to Main Routes
**File to modify**: `app.py`

**Routes to protect** (add `@login_required` decorator):
- Line ~506: `@app.route("/")` and `@app.route("/certs")`
- Line ~548: `@app.route("/sign")`
- Line ~617: `@app.route("/inspect", ...)`
- Line ~910: `@app.route("/update_validity", ...)`
- Line ~987: `@app.route("/server_ext", ...)`
- Line ~1031: `@app.route("/view/<int:cert_id>")`
- Line ~1104: `@app.route("/delete/<int:cert_id>", ...)`
- Line ~1132: `@app.route("/submit", ...)`
- Line ~1255: `@app.route("/revoke/<int:cert_id>", ...)`

**Make these routes PUBLIC** (no @login_required):
- `/register` - New route for registration
- `/login` - New route for login
- `/ocsp` - OCSP should remain public for certificate validation

#### Step 3.2: Modify Certificate List Query
**File to modify**: `app.py`
**Location**: Line ~510-540 (index function)

**Current code**:
```python
with sqlite3.connect(app.config["DB_PATH"]) as conn:
    cur = conn.cursor()
    cur.execute(
        "SELECT id, subject, serial, revoked, cert_pem FROM certificates"
    )
```

**Change to**:
```python
with sqlite3.connect(app.config["DB_PATH"]) as conn:
    cur = conn.cursor()
    if current_user.is_admin():
        # Admin sees all certificates with username
        cur.execute("""
            SELECT c.id, c.subject, c.serial, c.revoked, c.cert_pem, u.username
            FROM certificates c
            LEFT JOIN users u ON c.user_id = u.id
        """)
    else:
        # User sees only their certificates
        cur.execute("""
            SELECT c.id, c.subject, c.serial, c.revoked, c.cert_pem, u.username
            FROM certificates c
            LEFT JOIN users u ON c.user_id = u.id
            WHERE c.user_id = ?
        """, (current_user.id,))
```

#### Step 3.3: Modify Certificate Submission
**File to modify**: `app.py`
**Location**: Line ~1132-1190 (submit function)

**Current code** (line ~1189):
```python
conn.execute("INSERT INTO certificates (subject, serial, cert_pem) VALUES (?, ?, ?)",
             (subject_str, actual_serial, cert_pem))
```

**Change to**:
```python
conn.execute("INSERT INTO certificates (subject, serial, cert_pem, user_id) VALUES (?, ?, ?, ?)",
             (subject_str, actual_serial, cert_pem, current_user.id))
```

---

### Phase 4: Blueprint Modifications

#### Step 4.1: Modify x509_keys.py
**File to modify**: `x509_keys.py`

**Changes needed**:

1. **Import Flask-Login** (line ~7):
```python
from flask_login import login_required, current_user
```

2. **Add @login_required to routes**:
   - Line ~25: `@x509_keys_bp.route("/generate", ...)`
   - All other routes

3. **Filter keys by user** (line ~25 in generate_key POST):
```python
# After line 98 (before saving to DB):
new_key = Key(
    name=key_name,
    key_type=key_type,
    key_size=int(key_size) if key_type == "RSA" else None,
    curve_name=curve_name if key_type == "EC" else None,
    pqc_alg=pqc_alg if key_type == "PQC" else None,
    private_key=priv_data,
    public_key=pub_data,
    user_id=current_user.id  # ADD THIS LINE
)
```

4. **Filter key list query**:
Find the list_keys route and modify query:
```python
@x509_keys_bp.route("/keys", methods=["GET"])
@login_required
def list_keys():
    if current_user.is_admin():
        keys = Key.query.order_by(Key.created_at.desc()).all()
    else:
        keys = Key.query.filter_by(user_id=current_user.id).order_by(Key.created_at.desc()).all()
    # rest of code...
```

#### Step 4.2: Modify x509_profiles.py
**File to modify**: `x509_profiles.py`

**Similar changes**:
1. Import Flask-Login
2. Add @login_required to all routes
3. Add user_id when creating profiles
4. Filter profiles by user in list views

#### Step 4.3: Modify x509_requests.py
**File to modify**: `x509_requests.py`

**Location**: Line ~40 (generate_csr function)

**Changes needed**:

1. **Import Flask-Login** (line ~1):
```python
from flask_login import login_required, current_user
```

2. **Add @login_required** to all routes

3. **Filter keys/profiles in dropdowns** (line ~92-96):
```python
@x509_requests_bp.route("/requests/generate", methods=["GET", "POST"])
@login_required
def generate_csr():
    if request.method == "POST":
        # ... existing POST code with ownership validation ...
        
    # GET method - filter dropdowns
    from x509_keys import Key
    from x509_profiles import Profile
    
    if current_user.is_admin():
        keys = Key.query.order_by(Key.created_at.desc()).all()
        profiles = Profile.query.order_by(Profile.id.desc()).all()
    else:
        keys = Key.query.filter_by(user_id=current_user.id).order_by(Key.created_at.desc()).all()
        profiles = Profile.query.filter_by(user_id=current_user.id).order_by(Profile.id.desc()).all()
    
    return render_template("generate_csr.html", keys=keys, profiles=profiles)
```

4. **Add user_id when saving CSR** (line ~86):
```python
new_csr = CSR(
    name=csr_name, 
    key_id=key_obj.id, 
    profile_id=profile_obj.id, 
    csr_pem=csr_pem, 
    created_at=datetime.utcnow(),
    user_id=current_user.id  # ADD THIS LINE
)
```

5. **Add ownership validation** (before line ~50):
```python
# Verify user owns the key
if not current_user.is_admin():
    if key_obj.user_id != current_user.id:
        flash("You don't have permission to use this key.", "error")
        return redirect(url_for("requests.generate_csr"))
```

---

### Phase 5: HTML Template Modifications

#### Step 5.1: Create New Templates
**Location**: `html_templates/` directory

**New files to create**:
1. `register.html` - Registration page with validation
2. `login.html` - Login page
3. `manage_users.html` - Admin user management page

#### Step 5.2: Modify layout.html
**File to modify**: `html_templates/layout.html`

**Location**: Line ~60 (after existing navbar items, before version badge)

**Add**:
```html
</ul>
<!-- User info and logout -->
<ul class="navbar-nav ml-auto">
  {% if current_user.is_authenticated %}
    <li class="navbar-text text-light mr-3">
      👤 {{ current_user.username }}
      {% if current_user.is_admin() %}
        <span class="badge badge-danger">Admin</span>
      {% endif %}
    </li>
    {% if current_user.is_admin() %}
      <li class="nav-item">
        <a class="nav-link" href="{{ url_for('manage_users') }}">👥 Users</a>
      </li>
    {% endif %}
    <li class="nav-item">
      <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
    </li>
  {% endif %}
</ul>
```

#### Step 5.3: Modify list_certificates.html
**File to modify**: `html_templates/list_certificates.html`

**Location**: Line ~18 (table headers)

**Current**:
```html
<tr>
  <th>ID</th>
  <th>Common Name</th>
  <th>Serial</th>
  <th>Key</th>
  <th>Date (UTC)</th>
  <th>Status</th>
  <th>Actions</th>
</tr>
```

**Add User column** (only for admins):
```html
<tr>
  <th>ID</th>
  <th>Common Name</th>
  <th>Serial</th>
  <th>Key</th>
  <th>Date (UTC)</th>
  <th>Status</th>
  {% if current_user.is_admin() %}
  <th>User</th>
  {% endif %}
  <th>Actions</th>
</tr>
```

**Also update tbody** (line ~35):
```html
<td>
  {% if revoked %}
    <span>Revoked</span>
  {% elif expired %}
    <span>Expired</span>
  {% else %}
    <span>Active</span>
  {% endif %}
</td>
{% if current_user.is_admin() %}
<td>
  <span class="badge badge-info">{{ username or 'Unknown' }}</span>
</td>
{% endif %}
```

#### Step 5.4: Modify Other List Templates
**Files to modify**:
- `list_keys.html` - Add User column
- `list_csrs.html` - Add User column
- `list_profiles.html` - Add User column

Same pattern: Add column header and data cell with admin check.

#### Step 5.5: Modify sign.html and generate_csr.html
**Files to modify**: 
- `html_templates/sign.html`
- `html_templates/generate_csr.html`

**Changes**: Add username labels in dropdowns for admins (see instructions doc)

---

### Phase 6: Admin User Management Routes

#### Step 6.1: Add Admin Routes to app.py
**File to modify**: `app.py`

**Location**: After authentication routes (around line 600)

**Add routes**:
- `/admin/users` - List all users
- `/admin/users/create` - Create new user
- `/admin/users/<id>/role` - Change user role
- `/admin/users/<id>/delete` - Delete user

**Add admin_required decorator** (before routes):
```python
from functools import wraps

def admin_required(f):
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
```

---

## File Change Summary

### Files to Modify (Existing)
1. **app.py** (MAJOR changes)
   - Add Flask-Login setup
   - Add user model imports
   - Modify database initialization
   - Add authentication routes (register, login, logout)
   - Add admin routes
   - Protect existing routes with @login_required
   - Modify certificate queries to filter by user
   - Modify certificate insertion to include user_id

2. **x509_keys.py** (MODERATE changes)
   - Add user_id to Key model
   - Add Flask-Login imports
   - Add @login_required to all routes
   - Filter queries by user_id
   - Add user_id when creating keys

3. **x509_profiles.py** (MODERATE changes)
   - Add user_id to Profile model
   - Add Flask-Login imports
   - Add @login_required to all routes
   - Filter queries by user_id
   - Add user_id when creating profiles

4. **x509_requests.py** (MODERATE changes)
   - Add user_id to CSR model
   - Add Flask-Login imports
   - Add @login_required to all routes
   - Filter keys/profiles in dropdowns by user
   - Add ownership validation
   - Add user_id when creating CSRs

5. **html_templates/layout.html** (MINOR changes)
   - Add user info display
   - Add logout link
   - Add admin users link

6. **html_templates/list_certificates.html** (MINOR changes)
   - Add User column (admin only)

7. **html_templates/list_keys.html** (MINOR changes)
   - Add User column (admin only)

8. **html_templates/list_csrs.html** (MINOR changes)
   - Add User column (admin only)

9. **html_templates/list_profiles.html** (MINOR changes)
   - Add User column (admin only)

10. **html_templates/sign.html** (MINOR changes)
    - Add username labels in dropdowns (admin)

11. **html_templates/generate_csr.html** (MINOR changes)
    - Add username labels in dropdowns (admin)

### Files to Create (New)
1. **user_models.py** - User model and helper functions
2. **html_templates/register.html** - Registration page
3. **html_templates/login.html** - Login page
4. **html_templates/manage_users.html** - Admin user management

---

## Implementation Order

### Step-by-Step Execution Plan

**PHASE 1: Database & Models** (30 minutes)
1. Create `user_models.py`
2. Modify `app.py` database initialization
3. Modify SQLAlchemy models (Key, Profile, CSR)
4. Run app to create tables

**PHASE 2: Authentication** (45 minutes)
5. Modify `app.py` - Add Flask-Login setup
6. Add registration route to `app.py`
7. Add login/logout routes to `app.py`
8. Create `login.html` template
9. Create `register.html` template
10. Test registration and login

**PHASE 3: Route Protection** (30 minutes)
11. Add @login_required to main app.py routes
12. Add @login_required to blueprint routes
13. Modify certificate list query to filter by user
14. Modify certificate submission to include user_id
15. Test that routes require login

**PHASE 4: Multi-Tenancy** (60 minutes)
16. Modify x509_keys.py - Add user filtering
17. Modify x509_profiles.py - Add user filtering
18. Modify x509_requests.py - Add user filtering and ownership checks
19. Test user isolation

**PHASE 5: UI Updates** (45 minutes)
20. Modify layout.html - Add user info
21. Modify list_certificates.html - Add User column
22. Modify list_keys.html - Add User column
23. Modify list_csrs.html - Add User column
24. Modify list_profiles.html - Add User column
25. Modify sign.html - Update dropdowns
26. Modify generate_csr.html - Update dropdowns
27. Test UI displays correctly

**PHASE 6: Admin Features** (45 minutes)
28. Add admin_required decorator to app.py
29. Add admin user management routes to app.py
30. Create manage_users.html template
31. Test admin user management

**PHASE 7: Testing** (60 minutes)
32. Complete registration testing
33. Complete authentication testing
34. Complete multi-tenancy testing
35. Complete admin testing
36. Complete dropdown filtering testing
37. Security testing (URL manipulation, etc.)

**TOTAL ESTIMATED TIME: 5.25 hours**

---

## Database Migration Note

For existing installations, add this migration script to run ONCE:

```python
def migrate_existing_data():
    """One-time migration to add user_id to existing resources"""
    conn = sqlite3.connect(app.config["DB_PATH"])
    cur = conn.cursor()
    
    # Check if first user exists
    cur.execute("SELECT id FROM users ORDER BY id LIMIT 1")
    first_user = cur.fetchone()
    
    if first_user:
        admin_id = first_user[0]
        
        # Migrate existing certificates to admin
        cur.execute("UPDATE certificates SET user_id = ? WHERE user_id IS NULL", (admin_id,))
        
        conn.commit()
        print(f"Migrated existing resources to user ID {admin_id}")
    
    conn.close()
```

---

## Risk Analysis

### Low Risk Changes
- Template modifications (easy to revert)
- Adding new routes (doesn't break existing)
- Adding new models/columns (backward compatible)

### Medium Risk Changes
- Modifying certificate queries (test thoroughly)
- Adding @login_required (makes existing URLs inaccessible)

### High Risk Changes
- Database schema changes (test migration carefully)
- Modifying certificate submission (critical path)

### Mitigation Strategies
1. Backup database before starting
2. Test each phase independently
3. Keep original files as .bak
4. Use version control (git)
5. Test with multiple users immediately

---

## Testing Strategy

### Unit Tests Needed
- User model methods
- Password hashing/verification
- User helper functions

### Integration Tests Needed
- Registration flow
- Login flow
- Certificate creation with user association
- Multi-user isolation
- Admin access to all resources

### Manual Tests Needed
- All items in testing checklist from instructions
- Browser testing (forms, validation)
- Session persistence
- Dropdown filtering

---

## Rollback Plan

If issues occur:
1. Restore database backup
2. Revert file changes
3. Remove Flask-Login initialization
4. Remove @login_required decorators
5. Restore original templates

---

This plan provides complete guidance for implementing the user management system with minimal risk and maximum traceability.
