from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request, session as flask_session, current_app
from flask_login import login_required, current_user, logout_user, login_user, user_logged_in, user_logged_out
import uuid
import sqlite3
import re
from datetime import datetime, timedelta
from user_models import get_all_users, get_username_by_id

users_bp = Blueprint('users', __name__, url_prefix='/users')

# --- Flask-Login Signal Handlers ---
def _now_utc_str():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# --- Load MAX_IDLE_TIME config on blueprint registration ---
def init_users_config(app, config):
    app.config["MAX_IDLE_TIME"] = config.get("DEFAULT", "max_idle_time", fallback="7d")


def register_login_signals(app):

    @user_logged_in.connect_via(app)
    def track_user_logged_in(sender, user):
        current_app.logger.debug(f"track_user_logged_in: user_id={user.id} username={getattr(user, 'username', None)}")
        ensure_sessions_table()
        # Always generate a new sid on login to reset idle
        sid = str(uuid.uuid4())
        flask_session['sid'] = sid
        now_str = _now_utc_str()
        flask_session['last_activity'] = now_str
        current_app.logger.debug(f"track_user_logged_in: sid={sid} now_str={now_str}")
        db_path = current_app.config["DB_PATH"]
        current_app.logger.debug(f"track_user_logged_in: using DB_PATH={db_path}")
        with sqlite3.connect(db_path) as conn:
            # Always reset both login_time and last_activity to now on login
            conn.execute("INSERT OR REPLACE INTO user_sessions (session_id, user_id, login_time, last_activity) VALUES (?, ?, ?, ?)", (sid, user.id, now_str, now_str))
        current_app.logger.debug("track_user_logged_in: session row inserted/updated")

    @user_logged_out.connect_via(app)
    def track_user_logged_out(sender, user):
        current_app.logger.debug(f"track_user_logged_out: user_id={user.id} username={getattr(user, 'username', None)}")
        sid = flask_session.get('sid')
        if sid:
            current_app.logger.debug(f"track_user_logged_out: sid={sid}")
            db_path = current_app.config["DB_PATH"]
            current_app.logger.debug(f"track_user_logged_out: using DB_PATH={db_path}")
            with sqlite3.connect(db_path) as conn:
                conn.execute("DELETE FROM user_sessions WHERE session_id = ?", (sid,))
            flask_session.pop('sid', None)
            current_app.logger.debug("track_user_logged_out: session row deleted")



# --- Utility: Parse idle time config values like '20m', '1h', '4d' ---
def parse_idle_time(s):
    """
    Parse a string like '20m', '1h', '4d' into seconds.
    Supports:
      - m: minutes
      - h: hours
      - d: days
    Returns: int (seconds)
    """
    import re
    s = s.strip().lower()
    match = re.match(r"^(\d+)([mhd])$", s)
    if not match:
        raise ValueError(f"Invalid idle time format: {s}")
    value, unit = match.groups()
    value = int(value)
    if unit == 'm':
        return value * 60
    elif unit == 'h':
        return value * 3600
    elif unit == 'd':
        return value * 86400
    else:
        raise ValueError(f"Unknown unit: {unit}")



# --- Force logout if session missing from user_sessions table ---
@users_bp.before_app_request
def enforce_tracked_session():
    from flask import session as flask_session
    if not current_user.is_authenticated:
        return
    sid = flask_session.get('sid')
    if not sid:
        return

    db_path = current_app.config["DB_PATH"]
    now_str = _now_utc_str()
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT last_activity FROM user_sessions WHERE session_id = ?", (sid,)).fetchone()
    if not row:
        logout_user()
        flask_session.pop('sid', None)
        flash('You have been logged out by an administrator.', 'warning')
        return redirect(url_for('users.login'))
    # Idle timeout logic
    last_activity = row[0]
    max_idle_str = current_app.config.get('MAX_IDLE_TIME', '1h')
    try:
        max_idle_seconds = parse_idle_time(max_idle_str)
        if max_idle_seconds is None:
            max_idle_seconds = 3600
    except Exception:
        max_idle_seconds = 3600  # fallback 1h
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    try:
        last_dt = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        last_dt = now
    idle_seconds = (now - last_dt).total_seconds()
    current_app.logger.debug(f"[IDLE] enforce_tracked_session: sid={sid}")
    current_app.logger.debug(f"[IDLE] enforce_tracked_session: now_str={now_str}")
    current_app.logger.debug(f"[IDLE] enforce_tracked_session: last_activity={last_activity}")
    current_app.logger.debug(f"[IDLE] enforce_tracked_session: max_idle_str={max_idle_str} max_idle_seconds={max_idle_seconds}")
    current_app.logger.debug(f"[IDLE] enforce_tracked_session: idle_seconds={idle_seconds}")
    if idle_seconds > max_idle_seconds:
        current_app.logger.debug(f"[IDLE] enforce_tracked_session: FORCED LOGOUT due to idle (sid={sid}, idle_seconds={idle_seconds}, max_idle_seconds={max_idle_seconds})")
        logout_user()
        flask_session.pop('sid', None)
        flash('You have been logged out due to inactivity.', 'warning')
        return redirect(url_for('users.login'))
    # Only update last_activity if not idle
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE user_sessions SET last_activity = ? WHERE session_id = ?", (now_str, sid))




# --- Test endpoint to verify session DB writes ---
@users_bp.route('/test_session_db')
@login_required
def test_session_db():
    db_path = current_app.config["DB_PATH"]
    try:
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute("SELECT session_id, user_id, login_time, last_activity FROM user_sessions").fetchall()
        return jsonify({"db_path": db_path, "rows": [dict(zip(["session_id", "user_id", "login_time", "last_activity"], row)) for row in rows]})
    except Exception as e:
        return jsonify({"db_path": db_path, "error": str(e)})

def ensure_sessions_table():
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER,
            login_time TEXT,
            last_activity TEXT
        )''')
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(user_sessions)")
        cols = [row[1] for row in cur.fetchall()]
        if "last_activity" not in cols:
            conn.execute("ALTER TABLE user_sessions ADD COLUMN last_activity TEXT")
        conn.execute("""
            UPDATE user_sessions
            SET last_activity = login_time
            WHERE last_activity IS NULL OR last_activity = ''
        """)
        conn.commit()

def get_logged_in_user_ids():
    ensure_sessions_table()
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT DISTINCT user_id FROM user_sessions").fetchall()
        return set(row[0] for row in rows)

def get_user_idle_map():
    ensure_sessions_table()
    db_path = current_app.config["DB_PATH"]
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    idle = {}
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("""
            SELECT user_id, MAX(COALESCE(last_activity, login_time)) AS last_ts
            FROM user_sessions
            GROUP BY user_id
        """).fetchall()
    for user_id, last_ts in rows:
        try:
            parsed = datetime.strptime(last_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            continue
        delta = now - parsed
        if delta.total_seconds() < 0:
            continue
        minutes = int(delta.total_seconds() // 60)
        hours = minutes // 60
        minutes = minutes % 60
        idle[user_id] = f"{hours:02d}:{minutes:02d}"
    return idle

def get_auth_source_for_username(username):
    key = (username or "").lower()
    if not key:
        return "local"
    # Add logic for LDAP/local detection if needed
    return "local"


# --- Approve User (Admin Only) ---
@users_bp.route('/approve_user/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
    from user_models import get_user_by_id
    user = get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users.manage_users'))
    if user.status != 'pending':
        flash('User is not pending approval.', 'info')
        return redirect(url_for('users.manage_users'))
    import sqlite3
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash('User approved and activated.', 'success')
    return redirect(url_for('users.manage_users'))
# --- Toggle User Active (Admin Only) ---
@users_bp.route('/toggle_active/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_active(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
    from user_models import get_user_by_id
    user = get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users.manage_users'))
    # Toggle between 'active' and 'deactivated'
    import sqlite3
    new_status = 'deactivated' if user.status == 'active' else 'active'
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    cur = conn.cursor()
    cur.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    flash(f'User {"activated" if new_status == "active" else "deactivated"}.', 'success')
    return redirect(url_for('users.manage_users'))



@users_bp.route('/change_role/<int:user_id>', methods=['POST'])
@login_required
def change_role(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
    new_role = request.form.get('role')
    if new_role not in ('user', 'admin'):
        flash('Invalid role.', 'error')
        return redirect(url_for('users.manage_users'))
    from user_models import update_user_role
    update_user_role(user_id, new_role)
    flash('User role updated.', 'success')
    return redirect(url_for('users.manage_users'))

@users_bp.route('/manage')
@login_required
def manage_users():
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('index'))
    users = get_all_users()
    logged_in_ids = get_logged_in_user_ids()
    idle_map = get_user_idle_map()
    for user in users:
        user['is_logged_in'] = user['id'] in logged_in_ids
        user['auth_source'] = get_auth_source_for_username(user['username'])
        user['idle'] = idle_map.get(user['id'], '') if user['is_logged_in'] else ''
    return render_template('manage_users.html', users=users)

@users_bp.route('/api')
@login_required
def api_users():
    if not current_user.is_admin():
        return jsonify({'error': 'forbidden'}), 403
    users = get_all_users()
    logged_in_ids = get_logged_in_user_ids()
    idle_map = get_user_idle_map()
    user_list = []
    for user in users:
        user['auth_source'] = get_auth_source_for_username(user['username'])
        user_list.append({
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'email': user.get('email', ''),
            'status': user['status'],
            'is_logged_in': user['id'] in logged_in_ids,
            'auth_source': user.get('auth_source', 'local'),
            'idle': idle_map.get(user['id'], '') if user['id'] in logged_in_ids else ''
        })
    return jsonify({'users': user_list, 'current_user_id': current_user.id})

@users_bp.route('/admin_logout/<int:user_id>', methods=['POST'])
@login_required
def admin_logout(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
    if user_id == current_user.id:
        logout_user()
        flash('You have been logged out.', 'success')
        return redirect(url_for('users.login'))
    else:
        flash('User has been logged out from all sessions.', 'success')
        return redirect(url_for('users.manage_users'))

@users_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', 'user')
        email = request.form.get('email', '').strip() or None
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('add_user.html')
        from user_models import get_user_by_username, create_user_db
        if get_user_by_username(username):
            flash('Username already exists.', 'error')
            return render_template('add_user.html')
        user_id = create_user_db(username, password, role, email)
        if user_id:
            # Log event
            try:
                from events import log_event
                log_event(
                    event_type="create_user",
                    resource_type="user",
                    resource_name=username,
                    user_id=current_user.id,
                    details={"role": role, "email": email}
                )
            except Exception as e:
                pass
            flash('User added successfully.', 'success')
            return redirect(url_for('users.manage_users'))
        else:
            flash('Failed to add user.', 'error')
    return render_template('add_user.html')

@users_bp.route('/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        flash('Access denied: Admins only.', 'error')
        return redirect(url_for('users.manage_users'))
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('users.manage_users'))
    from user_models import get_username_by_id
    username = get_username_by_id(user_id)
    # Log event
    try:
        from events import log_event
        log_event(
            event_type="delete_user",
            resource_type="user",
            resource_name=username,
            user_id=current_user.id,
            details={}
        )
    except Exception as e:
        pass
    # You may want to add DB deletion logic here
    flash('User deleted.', 'success')
    return redirect(url_for('users.manage_users'))

@users_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        password_confirm = request.form.get("password_confirm", "").strip()
        email = request.form.get("email", "").strip()
        errors = []
        if not username:
            errors.append("Username is required.")
        elif len(username) < 6:
            errors.append("Username must be at least 6 characters.")
        elif len(username) > 20:
            errors.append("Username must not exceed 20 characters.")
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append("Username can only contain letters, numbers, and underscores.")
        if not password:
            errors.append("Password is required.")
        elif len(password) < 6:
            errors.append("Password must be at least 6 characters.")
        if password != password_confirm:
            errors.append("Passwords do not match.")
        if not email:
            errors.append("Email is required.")
        else:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                errors.append("Invalid email format.")
        if not errors:
            from user_models import get_user_by_username, create_user_db
            existing_user = get_user_by_username(username)
            if existing_user:
                errors.append("Username already exists.")
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("register.html")
        # Check if this is the first user (make them admin)
        conn = sqlite3.connect(current_app.config["DB_PATH"])
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        user_count = cur.fetchone()[0]
        conn.close()
        role = 'admin' if user_count == 0 else 'user'
        user_id = create_user_db(username, password, role, email or None)
        if user_id:
            if role == 'admin':
                flash("Account created successfully! You are the first user and have been granted admin privileges. You can now log in.", "success")
            else:
                flash("Account created and pending approval. Your registration is awaiting administrator review.", "info")
            current_app.logger.info(f"New user registered: {username} with role: {role}")
            return redirect(url_for('users.login'))
        else:
            flash("Registration failed. Please try again.", "error")
            return render_template("register.html")
    return render_template("register.html")

@users_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")
        from user_models import get_user_by_username, create_user_db, update_last_login
        user = get_user_by_username(username)
        if user:
            if user.status == 'deactivated':
                flash("User account is suspended. Contact administrator.", "error")
                current_app.logger.warning(f"Login attempt for suspended user: {username}")
            elif user.status == 'pending':
                flash("User account is pending approval by administrator.", "error")
                current_app.logger.warning(f"Login attempt for pending user: {username}")
            elif user.status == 'active' and user.check_password(password):
                login_user(user)
                update_last_login(user.id)
                current_app.logger.info(f"User {username} logged in")
                return redirect(url_for('index'))
            else:
                flash("Invalid username or password.", "error")
                current_app.logger.warning(f"Failed login attempt for: {username}")
        else:
            from ldap_utils import ldap_authenticate
            ldap_result = ldap_authenticate(username, password, current_app.config, current_app.logger)
            if ldap_result:
                user_id = create_user_db(username, password, role='user', email=ldap_result.get('email'), status='active', auth_source='ldap')
                # You may want to update LDAP_IMPORTED_USERS and LDAP_SOURCE_CACHE here
                user = get_user_by_username(username)
                if user and user.status == 'active':
                    login_user(user)
                    update_last_login(user.id)
                    current_app.logger.info(f"User {username} authenticated via LDAP and synced to local DB.")
                    return redirect(url_for('index'))
                else:
                    flash("LDAP authentication succeeded but local user could not be activated. Contact administrator.", "error")
                    current_app.logger.error(f"LDAP auth ok for {username} but local user creation/activation failed.")
            else:
                flash("Invalid username or password.", "error")
                current_app.logger.warning(f"Failed login attempt for: {username} (local + LDAP)")
    return render_template("login.html")

@users_bp.route('/logout')
@login_required
def logout():
    current_app.logger.info(f"User {current_user.username} logged out")
    logout_user()
    flask_session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('users.login'))

# --- Idle Timeout Parsing Helper ---
    # ...existing code...

# Add more user management routes as needed
