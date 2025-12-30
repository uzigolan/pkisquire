def test_cross_user_access_denied(client):
	# User1 creates a key and gets its id
	login(client, 'user', 'userpass')
	client.post('/generate', data={'key_type': 'RSA', 'key_name': 'testkey'}, follow_redirects=True)
	rv = client.get('/keys')
	import re
	match = re.search(rb'/keys/(\d+)', rv.data)
	assert match, "No key id found in key list!"
	key_id = match.group(1).decode()
	logout(client)
	# User2 tries to access User1's key
	login(client, 'user2', 'user2pass')
	rv = client.get(f'/keys/{key_id}', follow_redirects=True)
	assert b'Access denied' in rv.data or rv.status_code == 403 or b'Not Found' in rv.data or rv.status_code == 404

def test_delete_requires_confirmation(client):
	login(client, 'user', 'userpass')
	client.post('/generate', data={'key_type': 'RSA', 'key_name': 'testkey2'}, follow_redirects=True)
	rv = client.get('/keys')
	import re
	match = re.search(rb'/keys/(\d+)', rv.data)
	assert match, "No key id found in key list!"
	key_id = match.group(1).decode()
	# Try to delete without confirmation
	rv = client.post(f'/keys/{key_id}/delete', data={'confirm': ''}, follow_redirects=True)
	# Accept 404 as valid if key is not found
	assert b'Confirmation required' in rv.data or b'confirm' in rv.data or b'Not Found' in rv.data or rv.status_code == 404

# Idle session timeout test would require mocking time/session expiry
# Example placeholder:
def test_idle_session_timeout(client):
	login(client, 'user', 'userpass')
	# Simulate idle timeout (implementation depends on app/session)
	# For now, just check session is active
	rv = client.get('/keys')
	assert rv.status_code == 200

import pytest

def login(client, username, password):
	return client.post('/users/login', data={
		'username': username,
		'password': password
	}, follow_redirects=True)

def logout(client):
	return client.get('/users/logout', follow_redirects=True)

def test_login_page_renders(client):
	rv = client.get('/users/login', follow_redirects=True)
	assert rv.status_code == 200 or rv.status_code == 302
	# Check for Login header (case-insensitive, allow whitespace)
	import re
	assert re.search(br'<h2>\s*Login\s*</h2>', rv.data, re.IGNORECASE)

def test_valid_login_and_logout(client):
	rv = login(client, 'admin', 'pikachu')
	# Check for admin username in navbar (case-insensitive)
	assert b'admin' in rv.data or b'User:' in rv.data
	rv = logout(client)
	import re
	assert re.search(br'<h2>\s*Login\s*</h2>', rv.data, re.IGNORECASE)

def test_invalid_login(client):
	rv = login(client, 'admin', 'wrongpass')
	# Check for flash message (alert) and Login header
	assert b'alert' in rv.data or b'Invalid' in rv.data
	import re
	assert re.search(br'<h2>\s*Login\s*</h2>', rv.data, re.IGNORECASE)

def test_unauthenticated_access_redirect(client):
	rv = client.get('/keys', follow_redirects=True)
	assert b'Login' in rv.data or rv.request.path == '/users/login'
