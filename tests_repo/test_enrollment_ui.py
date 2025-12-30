def login(client, username, password):
	return client.post('/users/login', data={
		'username': username,
		'password': password
	}, follow_redirects=True)

"""
NOTE: SCEP and EST enrollment tests are now handled by the official PowerShell scripts in tests/scripts:
  - EST: test_estclient_go.ps1, test_estclient_go_mtls.ps1
  - SCEP: test_sscep.ps1, test_sscep_pass.ps1 (with challenge password argument)
To run these tests automatically, use the VS Code test task: 'Run SCEP/EST PowerShell Enrollment Tests'.
UI enrollment is still tested via Python UI tests.
"""
