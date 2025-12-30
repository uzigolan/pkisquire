from datetime import datetime, timezone
import pytz


def utc_to_local(utc_dt_str, local_tz_name=None):
    """
    Convert an ISO8601 UTC datetime string to local time.
    If local_tz_name is None, use the system's local timezone.
    """
    if not utc_dt_str:
        return None
    utc_dt = datetime.fromisoformat(utc_dt_str)
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    if local_tz_name:
        local_tz = pytz.timezone(local_tz_name)
    else:
        local_tz = datetime.now().astimezone().tzinfo
    return utc_dt.astimezone(local_tz)

# Example usage:
if __name__ == "__main__":
    utc_str = "2025-12-30T12:34:56.789012+00:00"
    print("Local time:", utc_to_local(utc_str))
