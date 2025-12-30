from datetime import datetime
from flask import Blueprint, render_template, request
import pytz

# Utility function to convert UTC ISO string to local time string

def utc_to_local_str(utc_dt_str, local_tz_name=None, fmt='%Y-%m-%d %H:%M:%S'):
    if not utc_dt_str:
        return ''
    dt = datetime.fromisoformat(utc_dt_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=pytz.UTC)
    if local_tz_name:
        local_tz = pytz.timezone(local_tz_name)
    else:
        local_tz = datetime.now().astimezone().tzinfo
    return dt.astimezone(local_tz).strftime(fmt)

# Jinja2 filter registration

def register_utc_to_local_filter(app):
    app.jinja_env.filters['utc_to_local'] = utc_to_local_str
