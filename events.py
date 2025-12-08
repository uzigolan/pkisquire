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
    query += " LIMIT ? OFFSET ?"
    params.extend([page_size, offset])
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
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 10))
    user_role = getattr(g, 'user_role', 'user')
    user_id = getattr(g, 'user_id', None)
    events = get_events_query(filters, sort, direction, page, page_size, user_role, user_id)
    # Map user_id to username for display
    from user_models import get_username_by_id
    def user_display(uid):
        # If uid is not an int, return as is (e.g., 'scep')
        try:
            return get_username_by_id(int(uid))
        except Exception:
            return str(uid)
    events_with_usernames = []
    for event in events:
        # event[4] is user_id
        event = list(event)
        event[4] = user_display(event[4])
        events_with_usernames.append(tuple(event))
    # Debug: log the events list to the server log
    try:
        current_app.logger.info(f"[DEBUG /events] Retrieved {len(events_with_usernames)} events: {events_with_usernames}")
    except Exception as e:
        current_app.logger.error(f"[DEBUG /events] Logging error: {e}")
    return render_template('events.html', events=events_with_usernames, page=page, page_size=page_size, sort=sort, direction=direction)

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
