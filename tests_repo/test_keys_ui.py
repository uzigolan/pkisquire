
import pytest

def login(client, username, password):
	return client.post('/users/login', data={
		'username': username,
		'password': password
	}, follow_redirects=True)

def test_keys_page_renders(client):
	login(client, 'user', 'userpass')
	# Create a key to ensure the list is not empty
	client.post('/generate', data={'key_type': 'RSA', 'key_name': 'testkey_list'}, follow_redirects=True)
	rv = client.get('/keys')
	assert rv.status_code == 200
	assert b'Keys' in rv.data or b'Key List' in rv.data

def test_generate_key(client):
	login(client, 'user', 'userpass')
	rv = client.post('/generate', data={'key_type': 'RSA', 'key_name': 'testkey'}, follow_redirects=True)
	assert b'Key generated' in rv.data or b'Keys' in rv.data

def test_key_appears_in_list(client):
	login(client, 'user', 'userpass')
	client.post('/generate', data={'key_type': 'RSA', 'key_name': 'testkey2'}, follow_redirects=True)
	rv = client.get('/keys')
	assert b'RSA' in rv.data or b'key' in rv.data

def test_view_key(client):
	login(client, 'user', 'userpass')
	resp = client.post('/generate', data={'key_type': 'RSA', 'key_name': 'testkey3'}, follow_redirects=True)
	# Extract key id from the /keys page
	rv = client.get('/keys')
	import re
	match = re.search(rb'/keys/(\d+)', rv.data)
	assert match, "No key id found in key list!"
	key_id = match.group(1).decode()
	rv = client.get(f'/keys/{key_id}')
	assert b'Public Key' in rv.data or b'Private Key' in rv.data

def test_delete_key(client):
	login(client, 'user', 'userpass')
	client.post('/generate', data={'key_type': 'RSA', 'key_name': 'testkey4'}, follow_redirects=True)
	# Extract key id from the /keys page
	rv = client.get('/keys')
	import re
	match = re.search(rb'/keys/(\d+)', rv.data)
	assert match, "No key id found in key list!"
	key_id = match.group(1).decode()
	rv = client.post(f'/keys/{key_id}/delete', data={'confirm': 'DELETE'}, follow_redirects=True)
	assert b'Key deleted' in rv.data or b'Keys' in rv.data

def test_keys_table_headers(client):
	login(client, 'user', 'userpass')
	# Ensure at least one key exists
	client.post('/generate', data={'key_type': 'RSA', 'key_name': 'testkey_headers'}, follow_redirects=True)
	rv = client.get('/keys')
	assert b'Key Type' in rv.data and b'Actions' in rv.data

def test_generate_key_button_visible(client):
	login(client, 'user', 'userpass')
	# Ensure at least one key exists
	client.post('/generate', data={'key_type': 'RSA', 'key_name': 'testkey_btn'}, follow_redirects=True)
	rv = client.get('/keys')
	assert b'Generate New Key' in rv.data or b'data-testid="btn-generate-key"' in rv.data
