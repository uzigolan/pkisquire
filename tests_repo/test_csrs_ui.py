
import pytest

def login(client, username, password):
	return client.post('/users/login', data={
		'username': username,
		'password': password
	}, follow_redirects=True)

def test_generate_csr(client):
	login(client, 'user', 'userpass')
	# Create a key and extract its id
	resp = client.post('/generate', data={'key_type': 'RSA', 'key_name': 'csrkey'}, follow_redirects=True)
	rv = client.get('/keys')
	import re
	match = re.search(rb'/keys/(\d+)', rv.data)
	assert match, "No key id found in key list!"
	key_id = match.group(1).decode()
	rv = client.post('/requests/generate', data={'key_id': key_id, 'subject': 'CN=test'}, follow_redirects=True)
	assert b'CSR generated' in rv.data or b'CSRs' in rv.data

def test_csr_appears_in_list(client):
	login(client, 'user', 'userpass')
	# Create a key and CSR
	client.post('/generate', data={'key_type': 'RSA', 'key_name': 'csrkey2'}, follow_redirects=True)
	rv = client.get('/keys')
	import re
	match = re.search(rb'/keys/(\d+)', rv.data)
	assert match, "No key id found in key list!"
	key_id = match.group(1).decode()
	client.post('/requests/generate', data={'key_id': key_id, 'subject': 'CN=test2'}, follow_redirects=True)
	rv = client.get('/requests')
	assert b'CSR' in rv.data or b'Pending' in rv.data

def test_sign_csr(client):
	# User creates key and CSR, admin signs it
	login(client, 'user', 'userpass')
	client.post('/generate', data={'key_type': 'RSA', 'key_name': 'csrkey3'}, follow_redirects=True)
	rv = client.get('/keys')
	import re
	match = re.search(rb'/keys/(\d+)', rv.data)
	assert match, "No key id found in key list!"
	key_id = match.group(1).decode()
	client.post('/requests/generate', data={'key_id': key_id, 'subject': 'CN=test3'}, follow_redirects=True)
	rv = client.get('/requests')
	csr_match = re.search(rb'/requests/(\d+)', rv.data)
	assert csr_match, "No CSR id found in CSR list!"
	csr_id = csr_match.group(1).decode()
	logout = lambda c: c.get('/users/logout', follow_redirects=True)
	logout(client)
	login(client, 'admin', 'pikachu')
	rv = client.get(f'/sign?id={csr_id}', follow_redirects=True)
	assert b'Certificate issued' in rv.data or b'Certificates' in rv.data
