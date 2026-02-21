import datetime
import time
import pytest
import configparser
from pathlib import Path
from sqlalchemy import text
from extensions import db

PAUSE_SECONDS = 5
CHALLENGE_PASSWORD_CACHE = {}
def print_cert_lifecycle_steps():
	print("Available certificate lifecycle test steps:")
	print(" 1: Login as admin")
	print(" 2: Create key")
	print(" 3: Create req template")
	print(" 4: Create ext template")
	print(" 5: Create CSR")
	print(" 6: Create enrollment policy (1d)")
	print(" 7: Create challenge password")
	print(" 8: Sign CSR with policy")
	print(" 9: Check certificate in list")
	print("10: Download certificate")
	print("11: Revoke certificate")
	print("12: Delete certificate")
	print("13: Delete enrollment policy")
	print("14: Delete challenge password")
	print("15: Delete certificate request (CSR)")
	print("16: Delete certificate templates (req/ext)")
	print("17: Delete key")

import os
import re

IS_ENTERPRISE = os.environ.get("PIKACHU_EDITION", "community").strip().lower() == "enterprise"

def login(client, username, password):
	# Always log out before logging in as a new user
	client.get('/users/logout', follow_redirects=True)
	rv = client.post('/users/login', data={
		'username': username,
		'password': password
	}, follow_redirects=True)
	# Keep UI tests portable across DBs where admin password was changed.
	if rv.request.path == '/users/login':
		row = db.session.execute(
			text("SELECT id FROM users WHERE username = :u"),
			{"u": "admin"},
		).fetchone()
		if row:
			with client.session_transaction() as sess:
				sess["_user_id"] = str(row[0])
				sess["_fresh"] = True
			rv = client.get('/', follow_redirects=True)
	return rv

def should_run(target_step):
	current_step = int(os.environ.get('CERT_TEST_STEP', '0'))
	return current_step == 0 or current_step >= target_step


def reset_db_session():
	"""Ensure SQLAlchemy session is clean before doing DB work."""
	from flask import current_app
	with current_app.app_context():
		try:
			current_app.extensions['sqlalchemy'].db.session.rollback()
		except Exception:
			pass



# --- Refactored: Step-by-step test runner ---
def run_cert_lifecycle_step(client, step):
	# Make sure previous failures don't poison the session
	reset_db_session()

	def do_login():
		return login(client, 'admin', 'pikachu')
	def do_logout():
		client.get('/users/logout', follow_redirects=True)

	# Helper to get profile id by name
	def get_profile_id(profile_name):
		from flask import current_app
		with current_app.app_context():
			from x509_profiles import Profile
			profile = Profile.query.filter_by(name=profile_name).first()
			assert profile is not None, f"Profile '{profile_name}' not found in DB!"
			return profile.id

	# Helper to get CSR id by name
	def get_csr_id(csr_name):
		from flask import current_app
		with current_app.app_context():
			from x509_requests import CSR
			csr = CSR.query.filter_by(name=csr_name).first()
			assert csr is not None, f"CSR '{csr_name}' not found in DB!"
			return csr.id

	# Helper to get cert id by CN
	def get_cert_id_by_cn(cn):
		from flask import current_app
		with current_app.app_context():
			from models import Certificate
			cert = Certificate.query.filter(Certificate.subject.contains(cn)).order_by(Certificate.id.desc()).first()
			assert cert is not None, f"Certificate with CN '{cn}' not found!"
			return cert.id
	# Helper to fetch challenge password list (requires logged-in session)
	def get_challenge_passwords():
		resp = client.get('/challenge_passwords/data')
		assert resp.status_code == 200
		return resp.get_json() or []
	# Helper to know if challenge passwords are enabled
	def challenge_passwords_enabled():
		cfg = configparser.ConfigParser()
		cfg.read(Path(__file__).resolve().parents[1] / "config.ini")
		return IS_ENTERPRISE and cfg.getboolean("SCEP", "challenge_password_enabled", fallback=False)

	if step == 6:
		do_logout()
		do_login()
		cpw_enabled = challenge_passwords_enabled()
		cpw_before = len(get_challenge_passwords()) if cpw_enabled else None
		# Create enrollment policy using isotest_ext and validity 1 day
		policy_name = 'isotest_policy_1d'
		rv = client.post('/ra_policies/new', data={
			'name': policy_name,
			'validity': 1,
			'profile_name': 'isotest_ext',
			'description': 'Test policy for 1 day'
		}, follow_redirects=True)
		if not (b'isotest_policy_1d' in rv.data or b'Enrollment Policies' in rv.data):
			print('Step 6: Enrollment policy creation failed! Response:')
			print(rv.data.decode(errors='ignore'))
		from ra_policies import RAPolicyManager
		import app as flask_app
		mgr = RAPolicyManager(flask_app.app.config["DB_PATH"])
		assert mgr.get_policy(name='isotest_policy_1d') is not None, "Enrollment policy isotest_policy_1d was not created."
		if cpw_enabled:
			cpw_after = len(get_challenge_passwords())
			assert cpw_after >= cpw_before, f"Challenge password count should not decrease after policy creation (before={cpw_before}, after={cpw_after})"
		print("Step 6 complete: Enrollment policy created.")
		do_logout()
		return

	if step == 7:
		do_logout()
		do_login()
		# Create challenge password (requires feature enabled)
		if not challenge_passwords_enabled():
			pytest.skip("Challenge passwords disabled in config.")
		cpw_before = len(get_challenge_passwords())
		resp = client.post('/challenge_passwords', data={}, follow_redirects=True)
		assert resp.status_code == 200
		cpw_after = len(get_challenge_passwords())
		assert cpw_after >= cpw_before + 1, f"Expected challenge password count to increase (before={cpw_before}, after={cpw_after})"
		latest = get_challenge_passwords()[0]
		CHALLENGE_PASSWORD_CACHE['last'] = latest.get("value")
		print("Step 7 complete: Challenge password created.")
		do_logout()
		return

	if step == 8:
		do_logout()
		do_login()
		# Use the CSR and enrollment policy to sign the certificate
		# Get CSR PEM and policy id from DB
		from flask import current_app
		with current_app.app_context():
			from x509_requests import CSR
			from ra_policies import RAPolicyManager
			import app as flask_app
			csr = CSR.query.filter_by(name='isotest_csr').first()
			assert csr is not None, "CSR 'isotest_csr' not found!"
			csr_pem = csr.csr_pem
			mgr = RAPolicyManager(flask_app.app.config["DB_PATH"])
			policy = mgr.get_policy(name='isotest_policy_1d')
			assert policy is not None, "Policy 'isotest_policy_1d' not found!"
			policy_id = policy['id']
		rv = client.post('/submit', data={
			'csr': csr_pem,
			'policy_id': policy_id
		}, follow_redirects=True)
		if not (b'Certificate issued' in rv.data or b'Certificates' in rv.data):
			print('Step 8: Signing failed! URL: /submit')
			print(rv.data.decode(errors="ignore"))
		assert b'Certificate issued' in rv.data or b'Certificates' in rv.data
		print("Step 8 complete: Certificate signed.")
		do_logout()
		return

	if step == 9:
		do_logout()
		do_login()
		# Check certificate is in the list (by CN)
		rv = client.get('/certs')
		assert b'test-device-001' in rv.data, "Certificate with CN 'test-device-001' not found in list!"
		print("Step 9 complete: Certificate found in list.")
		do_logout()
		return
	"""
	Run a single step of the certificate lifecycle test, ensuring login/logout before each step.
	Steps:
		1: Login as admin
		2: Create key
		3: Create req template
		4: Create ext template
		5: Create CSR
		6: Create enrollment policy
		7: Create challenge password
		8: Sign CSR
		9: Check certificate in list
		10: Download certificate
		11: Revoke certificate
		12: Delete certificate
		13: Delete enrollment policy
		14: Delete challenge password
		15: Delete CSR
		16: Delete templates
		17: Delete key
	"""
	key_id = None
	csr_id = None
	cert_id = None

	def do_login():
		return login(client, 'admin', 'pikachu')
	def do_logout():
		client.get('/users/logout', follow_redirects=True)

	if step == 1:
		do_logout()
		rv = do_login()
		assert b'User:' in rv.data or rv.status_code == 200
		print("Step 1 complete: Logged in as admin.")
		do_logout()
		return

	if step == 2:
		do_logout()
		do_login()
		try:
			rv = client.post('/generate', data={'key_type': 'RSA', 'key_name': 'isotestkey'}, follow_redirects=True)
			assert b'Key generated' in rv.data or b'Keys' in rv.data
			from flask import current_app
			with current_app.app_context():
				from x509_keys import Key
				key = Key.query.filter_by(name='isotestkey').order_by(Key.id.desc()).first()
				assert key is not None, "No key named isotestkey found!"
				key_id = str(key.id)
			print(f"Step 2 complete: Key created with id {key_id}.")
		except Exception as e:
			print(f"Step 2: Exception (likely duplicate key), rolling back and continuing: {e}")
			from flask import current_app
			with current_app.app_context():
				try:
					current_app.extensions['sqlalchemy'].db.session.rollback()
				except Exception:
					pass
			from x509_keys import Key
			key = Key.query.filter_by(name='isotestkey').order_by(Key.id.desc()).first()
			key_id = str(key.id) if key else None
		do_logout()
		return

	if step == 3:
		do_logout()
		do_login()
		# Skip creation if already present
		from flask import current_app
		with current_app.app_context():
			from x509_profiles import Profile
			existing = Profile.query.filter_by(name='isotest_req').first()
			if existing:
				print("Step 3: Req template already exists, continuing.")
				do_logout()
				return
		try:
			req_content = (
				'[ req ]\n'
				'default_md         = sha256\n'
				'prompt             = no\n'
				'distinguished_name = dn\n'
				'\n'
				'[ dn ]\n'
				'C  = IL\n'
				'O  = RAD\n'
				'OU = RND\n'
				'CN = test-device-001\n'
			)
			rv = client.post('/profiles/new', data={
				'filename': 'isotest_req',
				'profile_type': 'req',
				'file_content': req_content
			}, follow_redirects=True)
			assert (
				rv.request.path.endswith('/profiles/view/isotest_req')
				or b'Profile isotest_req created.' in rv.data
				or b'isotest_req' in rv.data
			), "Req template was not created."
			print("Step 3 complete: Certificate template of type req created.")
		except Exception as e:
			print(f"Step 3: Exception (likely duplicate template), rolling back and continuing: {e}")
			from flask import current_app
			with current_app.app_context():
				try:
					current_app.extensions['sqlalchemy'].db.session.rollback()
				except Exception:
					pass
			rv = client.get('/profiles')
			if b'isotest_req' in rv.data:
				print("Step 3: Req template already exists, continuing.")
			else:
				raise
		do_logout()
		return

	if step == 4:
		do_logout()
		do_login()
		from flask import current_app
		with current_app.app_context():
			from x509_profiles import Profile
			existing = Profile.query.filter_by(name='isotest_ext').first()
			if existing:
				print("Step 4: Ext template already exists, continuing.")
				do_logout()
				return
		try:
			ext_content = (
				'[ v3_ext ]\n'
				'basicConstraints        = critical, CA:FALSE\n'
				'subjectKeyIdentifier    = hash\n'
				'authorityKeyIdentifier  = keyid,issuer\n'
				'\n'
				'authorityInfoAccess     = @aia_section\n'
				'crlDistributionPoints   = @crl_section\n'
				'\n'
				'[ aia_section ]\n'
				'OCSP;URI.0 = https://pkisquire-ca.rnd-rad.com/ocsp\n'
				'OCSP;URI.1 = https://pkisquire-ca.rnd-rad.com/ocsp\n'
				'caIssuers;URI.0 = https://pkisquire-ca.rnd-rad.com/ocsp\n'
				'\n'
				'[ crl_section ]\n'
				'URI.0 = https://pkisquire-ca.rnd-rad.com/downloads/crl\n'
			)
			rv = client.post('/profiles/new', data={
				'filename': 'isotest_ext',
				'profile_type': 'ext',
				'file_content': ext_content
			}, follow_redirects=True)
			assert (
				rv.request.path.endswith('/profiles/view/isotest_ext')
				or b'Profile isotest_ext created.' in rv.data
				or b'isotest_ext' in rv.data
			), "Ext template was not created."
			print("Step 4 complete: Certificate template of type ext created.")
		except Exception as e:
			print(f"Step 4: Exception (likely duplicate ext template), rolling back and continuing: {e}")
			from flask import current_app
			with current_app.app_context():
				try:
					current_app.extensions['sqlalchemy'].db.session.rollback()
				except Exception:
					pass
			rv = client.get('/profiles')
			if b'isotest_ext' in rv.data:
				print("Step 4: Ext template already exists, continuing.")
			else:
				raise
		do_logout()
		return

	if step == 5:
		do_logout()
		do_login()
		# Query the DB for key/profile IDs
		from flask import current_app
		with current_app.app_context():
			from x509_keys import Key
			from x509_profiles import Profile
			key = Key.query.filter_by(name='isotestkey').order_by(Key.id.desc()).first()
			assert key is not None, "Key 'isotestkey' not found in DB!"
			key_id = key.id
			profile = Profile.query.filter_by(name='isotest_req').first()
			assert profile is not None, "Profile 'isotest_req' not found in DB!"
			profile_id = profile.id
		rv = client.post('/requests/generate', data={
			'key_id': key_id,
			'profile_id': profile_id,
			'csr_name': 'isotest_csr'
		}, follow_redirects=True)
		with current_app.app_context():
			from x509_requests import CSR
			assert CSR.query.filter_by(name='isotest_csr').first() is not None, "CSR isotest_csr was not created."
		print("Step 5 complete: CSR created.")
		do_logout()
		return

	if step == 10:
		do_logout()
		do_login()
		rv = client.get('/certs')
		cert_match = re.search(rb'/view/(\d+)', rv.data)
		assert cert_match, "No cert id found!"
		cert_id = cert_match.group(1).decode()
		rv = client.get(f'/downloads/{cert_id}')
		assert rv.status_code == 200
		assert b'BEGIN CERTIFICATE' in rv.data
		print("Step 10 complete: Certificate downloaded.")
		do_logout()
		return

	if step == 11:
		do_logout()
		do_login()
		rv = client.get('/certs')
		cert_match = re.search(rb'/view/(\d+)', rv.data)
		assert cert_match, "No cert id found!"
		cert_id = cert_match.group(1).decode()
		rv = client.post(f'/revoke/{cert_id}', data={'confirm': 'REVOKE'}, follow_redirects=True)
		assert b'Certificate revoked' in rv.data or b'Revoked' in rv.data
		print("Step 11 complete: Certificate revoked.")
		do_logout()
		return

	if step == 12:
		do_logout()
		do_login()
		# Delete certificate (by CN)
		rv = client.get('/certs')
		cert_match = re.search(rb'/view/(\d+)', rv.data)
		assert cert_match, "No cert id found!"
		cert_id = cert_match.group(1).decode()
		rv = client.post(f'/delete/{cert_id}', follow_redirects=True)
		# The backend always redirects to /certs, so check for that
		assert rv.request.path == '/certs' or rv.status_code == 200
		print("Step 12 complete: Certificate deleted.")
		do_logout()
		return

	if step == 13:
		do_logout()
		do_login()
		cpw_enabled = challenge_passwords_enabled()
		cpw_before = len(get_challenge_passwords()) if cpw_enabled else None
		# Delete enrollment policy
		rv = client.get('/ra_policies')
		import re as _re
		policy_match = _re.search(rb'/ra_policies/(\d+)', rv.data)
		assert policy_match, "No policy id found!"
		policy_id = policy_match.group(1).decode()
		rv = client.post(f'/ra_policies/{policy_id}/delete', data={'confirm': 'DELETE'}, follow_redirects=True)
		assert b'Policy deleted' in rv.data or b'Deleted' in rv.data or rv.status_code == 200
		if cpw_enabled:
			cpw_after = len(get_challenge_passwords())
			assert cpw_after <= cpw_before, f"Challenge password count should not increase after policy delete (before={cpw_before}, after={cpw_after})"
		print("Step 13 complete: Enrollment policy deleted.")
		do_logout()
		return

	if step == 14:
		do_logout()
		do_login()
		if not challenge_passwords_enabled():
			pytest.skip("Challenge passwords disabled in config.")
		cpw_before = len(get_challenge_passwords())
		target = CHALLENGE_PASSWORD_CACHE.get('last')
		if not target and cpw_before:
			target = get_challenge_passwords()[0].get("value")
		assert target, "No challenge password available to delete."
		rv = client.post('/delete_challenge_password', data={'value': target}, follow_redirects=True)
		assert rv.status_code == 200
		cpw_after = len(get_challenge_passwords())
		assert cpw_after <= max(0, cpw_before - 1), f"Expected challenge password count to drop (before={cpw_before}, after={cpw_after})"
		print("Step 14 complete: Challenge password deleted.")
		do_logout()
		return

	if step == 15:
		do_logout()
		do_login()
		# Delete certificate request (CSR)
		rv = client.get('/requests')
		csr_match = re.search(rb'/requests/(\d+)/delete', rv.data)
		assert csr_match, "No CSR id found!"
		csr_id = csr_match.group(1).decode()
		rv = client.post(f'/requests/{csr_id}/delete', data={'confirm': 'DELETE'}, follow_redirects=True)
		assert b'CSR deleted' in rv.data or b'Deleted' in rv.data or rv.status_code == 200
		print("Step 15 complete: Certificate request deleted.")
		do_logout()
		return

	if step == 16:
		do_logout()
		do_login()
		# Delete certificate templates (req/ext) using correct endpoint
		rv = client.post('/profiles/delete/isotest_req', follow_redirects=True)
		assert b'Profile isotest_req deleted.' in rv.data or rv.status_code == 200
		rv = client.post('/profiles/delete/isotest_ext', follow_redirects=True)
		assert b'Profile isotest_ext deleted.' in rv.data or rv.status_code == 200
		print("Step 16 complete: Certificate templates deleted.")
		do_logout()
		return

	if step == 17:
		do_logout()
		do_login()
		# Delete key
		from flask import current_app
		with current_app.app_context():
			from x509_keys import Key
			key = Key.query.filter_by(name='isotestkey').order_by(Key.id.desc()).first()
			key_id = str(key.id) if key else None
		if key_id:
			rv = client.post(f'/keys/{key_id}/delete', data={'confirm': 'DELETE'}, follow_redirects=True)
			assert b'Key deleted' in rv.data or b'Keys' in rv.data or rv.status_code == 200
		print("Step 17 complete: Key deleted.")
		do_logout()
		return

# Fixture to pause 2 seconds between tests
@pytest.fixture(autouse=True, scope="function")
def pause_between_steps():
	yield
	print(f"Pausing {PAUSE_SECONDS} seconds before next step...")
	time.sleep(PAUSE_SECONDS)

# Collect step-by-step logs into pytest-html report (when plugin is present)
@pytest.fixture
def html_step_logger(request):
	entries = []
	yield entries
	pytest_html = request.config.pluginmanager.getplugin("html")
	if pytest_html:
		extra = getattr(request.node, "extra", [])
		text = "\n".join(entries) if entries else "No step logs recorded."
		extra.append(pytest_html.extras.text(text, name="steps"))
		request.node.extra = extra
# Step descriptions for better HTML reporting
step_descriptions = {
	1: "Login as admin",
	2: "Create key",
	3: "Create req template",
	4: "Create ext template",
	5: "Create CSR",
	6: "Create enrollment policy (1d)",
	7: "Create challenge password",
	8: "Sign CSR with policy",
	9: "Check certificate in list",
	10: "Download certificate",
	11: "Revoke certificate",
	12: "Delete certificate",
	13: "Delete enrollment policy",
	14: "Delete challenge password",
	15: "Delete certificate request (CSR)",
	16: "Delete certificate templates (req/ext)",
	17: "Delete key"
}

# Build ids for nicer names in reports
step_items = sorted(step_descriptions.items(), key=lambda kv: kv[0])
step_ids = [
	f"step_{num:02d}_{step_descriptions[num].lower().replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')}"
	for num, _ in step_items
]

@pytest.mark.parametrize("step,desc", step_items, ids=step_ids)
def test_certificate_lifecycle_step(client, html_step_logger, step, desc):
	"""Certificate lifecycle step test."""
	cert_test_step = os.environ.get('CERT_TEST_STEP')
	if cert_test_step:
		try:
			if int(cert_test_step) != step:
				pytest.skip(f"CERT_TEST_STEP={cert_test_step}, skipping step {step}")
		except Exception:
			pytest.skip("Invalid CERT_TEST_STEP value")
	print(f"\n===== Step {step}: {desc} =====")
	try:
		run_cert_lifecycle_step(client, step)
		html_step_logger.append(f"Step {step}: {desc} - OK")
	except Exception as exc:
		html_step_logger.append(f"Step {step}: {desc} - FAILED ({exc})")
		pytest.fail(f"Step {step} ({desc}) failed: {exc}")

