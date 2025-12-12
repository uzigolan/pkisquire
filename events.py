import sqlite3
from flask_login import current_user

from flask import Blueprint, request, render_template, g, current_app, abort
import sqlite3
from datetime import datetime
import json

bp = Blueprint('events', __name__, url_prefix='/events')

# Utility: log an event
def log_event(event_type, resource_type, resource_name, user_id, details=None):
    db_path = current_app.config['DB_PATH']
    ts = datetime.utcnow().isoformat()
    details_str = json.dumps(details) if details else None
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO events (event_type, resource_type, resource_name, user_id, timestamp, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (event_type, resource_type, resource_name, user_id, ts, details_str)
        )

def get_events_query(filters, sort, direction, page, page_size, user_role, user_id):
    db_path = current_app.config['DB_PATH']
    query = "SELECT * FROM events WHERE 1=1"
    params = []
    # Role-based filtering
    if user_role != 'admin':
        query += " AND user_id = ?"
        params.append(user_id)
        # Exclude user add/delete events
        query += " AND NOT (resource_type = 'user' AND (event_type = 'create' OR event_type = 'delete'))"
    # Apply filters (resource_type, event_type, etc.)
    for key, value in filters.items():
        query += f" AND {key} = ?"
        params.append(value)
    # Sorting
    if sort:
        dir_sql = 'ASC' if direction == 'asc' else 'DESC'
        query += f" ORDER BY {sort} {dir_sql}"
    else:
        query += " ORDER BY timestamp DESC"
    # Pagination
    offset = (page - 1) * page_size
    # Fetch one extra row to check if there is a next page
    query += " LIMIT ? OFFSET ?"
    params.extend([page_size + 1, offset])
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        return cur.fetchall()


def log_user_event(event_type, user_id, details=None):
    """
    Log a user event to the user_events table.
    event_type: str (e.g., 'login', 'logout', 'delete', 'create')
    user_id: int
    details: dict (optional)
    """
    db_path = current_app.config['DB_PATH']
    ts = datetime.utcnow().isoformat()
    import json
    details_str = json.dumps(details) if details else None
    # Extract username and actor info from details
    username = None
    actor_id = None
    actor_username = None
    if details:
        username = details.get('username')
        actor_id = details.get('by')
        actor_username = details.get('actor_username')
    if username is None:
        try:
            from user_models import get_username_by_id
            username = get_username_by_id(user_id)
        except Exception:
            username = None
    if actor_id is not None and actor_username is None:
        try:
            from user_models import get_username_by_id
            actor_username = get_username_by_id(actor_id)
        except Exception:
            actor_username = None
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO user_events (event_type, user_id, username, actor_id, actor_username, timestamp, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (event_type, user_id, username, actor_id, actor_username, ts, details_str)
        )

def get_user_events(user_id=None, event_type=None, page=1, page_size=20):
    """
    Query user events from the user_events table.
    Optionally filter by user_id and event_type.
    Returns a list of events.
    """
    db_path = current_app.config['DB_PATH']
    query = "SELECT * FROM user_events WHERE 1=1"
    params = []
    if user_id is not None:
        query += " AND user_id = ?"
        params.append(user_id)
    if event_type is not None:
        query += " AND event_type = ?"
        params.append(event_type)
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([page_size, (page-1)*page_size])
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        return cur.fetchall()


@bp.route('/', methods=['GET'])
def list_events():
    # Example: get filters from query params
    filters = {}
    for key in ['resource_type', 'event_type', 'resource_name']:
        v = request.args.get(key)
        if v:
            filters[key] = v
    sort = request.args.get('sort', 'timestamp')
    direction = request.args.get('direction', 'desc')
    user_role = getattr(g, 'user_role', 'user')
    user_id = getattr(g, 'user_id', None)
    # Fetch ALL events for client-side pagination
    events = get_events_query(filters, sort, direction, 1, 100000, user_role, user_id)
    show_user_column = user_role == 'admin'
    if show_user_column:
        from user_models import get_username_by_id
        def user_display(uid):
            try:
                return get_username_by_id(int(uid))
            except Exception:
                return str(uid)
        events_with_usernames = []
        for event in events:
            event = list(event)
            event[4] = user_display(event[4])
            events_with_usernames.append(tuple(event))
        events_to_render = events_with_usernames
    else:
        events_to_render = events
    try:
        current_app.logger.debug(f"[DEBUG /events] Retrieved {len(events_to_render)} events: {events_to_render}")
    except Exception as e:
        current_app.logger.error(f"[DEBUG /events] Logging error: {e}")
    return render_template('events.html', events=events_to_render, show_user_column=show_user_column)


@bp.route('/api', methods=['GET'])
def events_api():
    filters = {}
    for key in ['resource_type', 'event_type', 'resource_name']:
        v = request.args.get(key)
        if v:
            filters[key] = v
    sort = request.args.get('sort', 'timestamp')
    direction = request.args.get('direction', 'desc')
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 10))
    user_role = getattr(g, 'user_role', 'user')
    user_id = getattr(g, 'user_id', None)
    events = get_events_query(filters, sort, direction, page, page_size, user_role, user_id)
    has_next = len(events) > page_size
    events = events[:page_size]
    show_user_column = user_role == 'admin'
    current_app.logger.debug(f"[AJAX /events/api] role={user_role} user_id={user_id} events_count={len(events)}")
    if show_user_column:
        from user_models import get_username_by_id
        def user_display(uid):
            try:
                return get_username_by_id(int(uid))
            except Exception:
                return str(uid)
        events_with_usernames = []
        for event in events:
            event = list(event)
            event[4] = user_display(event[4])
            events_with_usernames.append(event)
        events_to_render = events_with_usernames
    else:
        events_to_render = [list(event) for event in events]
    current_app.logger.debug(f"[AJAX /events/api] events_to_render: {events_to_render}")
    return {'events': events_to_render, 'has_next': has_next}
# --- User Events Logic ---



@bp.route('/<int:event_id>', methods=['GET'])
def event_detail(event_id):
    db_path = current_app.config['DB_PATH']
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM events WHERE event_id = ?", (event_id,))
        event = cur.fetchone()
        if not event:
            abort(404)
    return render_template('event_detail.html', event=event)
