import os
import tempfile
import pytest
from flask import Flask
from app import app as flask_app
from datetime import datetime

@pytest.fixture(scope='session')
def app():
    os.environ['FLASK_ENV'] = 'testing'
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['LOGIN_DISABLED'] = False
    with flask_app.app_context():
        yield flask_app

@pytest.fixture
def client(app):
    return app.test_client()


def pytest_configure(config):
    # Add local timestamp to pytest-html Environment section
    local_ts = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    metadata = getattr(config, "_metadata", None)
    if isinstance(metadata, dict):
        metadata["Local time"] = local_ts
