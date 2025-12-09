# User Events Feature - TODO List

## 1. Plan events table schema
- Fields:
  - event_id (PK, autoincrement)
  - event_type (string: create, update, delete, etc.)
  - resource_type (string: keys, profiles, policies, requests, challenge_password, certificate, users, ...)
  - resource_name (string)
  - user_id (string or int)
  - timestamp (datetime)
  - details (text/json)
- Schema must support filtering, sorting, extensibility.

## 2. Add [EVENTS] section to config.ini
- Purpose: event logging policy (log level, retention, etc.)
- Policy must be checked before DB transaction.
- Example:
  ```ini
  [EVENTS]
  log_level = INFO
  retention_days = 90
  enabled = true
  ```

## 3. Design events route endpoint
- List/filter events with multi-keyword search, sorting, and pagination (20/25/50 rows, previous/next).
- UI must match current table look and feel.
- API endpoints for querying/filtering events by user, resource, action, date, etc.

## 4. Add events table to DB scripts
- Update init_db.py and migrate_db.py to create/alter events table.
- Do not modify app.py for table creation.

## 5. Create events.py blueprint
- All event logic and routes go here.
- Handle event logging, querying, and management.

## 6. Integrate event logging into CRUD
- Add event logging to all resource CRUD operations (keys, profiles, policies, requests/CSRs, challenge passwords, certificates, users, etc.).
- Log user, action, resource, and details for each event.


## 8. Add new layout item 'Events' before APIs
- Update main layout/navigation to include an 'Events' item before 'APIs'.
- Ensure consistent look and feel with other navigation items.

## 9. Role-based event visibility
- Admin users can view all events for all users.
- Regular users can only view their own events.

## 10. DB table creation constraint
- Ensure events table is created/altered only via init_db.py or migrate_db.py (never app.py).

## 11. Certificate source tracking in events
- Event details should indicate if a certificate was created via UI, SCEP, or EST.
