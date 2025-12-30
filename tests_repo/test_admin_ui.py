import pytest
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

def login(client, username, password):
	# Always log out before logging in as a new user
	client.get('/users/logout', follow_redirects=True)
	resp = client.post('/users/login', data={
		'username': username,
		'password': password
	}, follow_redirects=True)
	print(f"LOGIN POST ({username}): status={resp.status_code}")
	print(resp.data[:500])
	return resp

def test_user_cannot_access_admin_pages(client):
	login(client, 'user', 'userpass')
	rv = client.get('/users/manage', follow_redirects=True)
	assert b'Access denied' in rv.data or rv.status_code == 403 or b'Login' in rv.data

def test_admin_can_access_admin_pages(client):
	login_response = login(client, 'admin', 'pikachu')
	print("LOGIN RESPONSE:", login_response.data[:500])
	print("LOGIN RESPONSE HEADERS:", login_response.headers)
	# Debug current_user after login
	debug_resp = client.get('/debug_current_user')
	print("DEBUG /debug_current_user:", debug_resp.data)
	rv = client.get('/users/manage', follow_redirects=True)
	print("/users/manage RESPONSE:", rv.data[:500])
	assert rv.status_code == 200
	# Check for Users button in navbar
	assert b'class=\"btn btn-sm btn-warning ml-2\"' in rv.data and b'>Users<' in rv.data

def test_admin_ui_elements_visible(client):
	login(client, 'admin', 'pikachu')
	rv = client.get('/', follow_redirects=True)
	# Check for admin_test username and Users button in navbar
	print("ADMIN UI HTML:", rv.data[:1000])
	assert b'admin' in rv.data
	# Check for Users button in navbar
	assert b'class="btn btn-sm btn-warning ml-2"' in rv.data or b'>Users<' in rv.data

def test_user_ui_elements_hidden(client):
	login(client, 'user', 'userpass')
	rv = client.get('/')
	assert b'Users' not in rv.data and b'Admin' not in rv.data

def test_admin_can_download_certificate(client):
	login(client, 'admin', 'pikachu')
	rv = client.get('/downloads/1')
	assert rv.status_code == 200
	assert b'BEGIN CERTIFICATE' in rv.data
	# Optionally, check if the cert is parsable by cryptography
	try:
		load_pem_x509_certificate(rv.data, default_backend())
	except Exception as e:
		assert False, f"Certificate is not valid: {e}"


def test_admin_user_can_login_and_access_admin_pages(client):
	"""Test that admin_user can log in and access admin pages."""
	login_response = login(client, 'admin', 'pikachu')
	print("LOGIN RESPONSE (admin_user):", login_response.data[:500])
	assert login_response.status_code == 200
	# Debug current_user after login
	debug_resp = client.get('/debug_current_user')
	print("DEBUG /debug_current_user (admin_user):", debug_resp.data)
	rv = client.get('/users/manage', follow_redirects=True)
	print("/users/manage RESPONSE (admin_user):", rv.data[:500])
	assert rv.status_code == 200
	# Check for Users button in navbar
	assert b'class=\"btn btn-sm btn-warning ml-2\"' in rv.data and b'>Users<' in rv.data
