from datetime import datetime
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo

def add_local_created_at(profiles):
    for p in profiles:
        dt = p.created_at
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=ZoneInfo("UTC"))
            p.created_at_local = dt.astimezone()
        else:
            p.created_at_local = None
    return profiles
