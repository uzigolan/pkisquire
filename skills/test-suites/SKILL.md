# Skill: Test Suites (UI & API)

## Purpose
Run the UI and API certificate test suites and the underlying PowerShell protocol scripts in a repeatable way.

## When to use
- You want to run the full UI flow or the full API flow.
- You want to run a single UI step or a targeted API subset.
- You want a bundled test run that drives the PowerShell scripts in `tests/scripts`.

## Preconditions
- Activate venv: `\.venv\Scripts\activate`
- Install deps: `pip install -r requirements.txt`
- Always run from repo root and set PYTHONPATH: `$env:PYTHONPATH = (Resolve-Path .)`
- API extras:
  - `estclient` installed in WSL (default `~/go/bin/estclient`)
  - WSL `/etc/hosts` maps `localhost-wsl-win` to your Windows IP
  - `config.ini` has valid CA chain and trusted cert/key paths

## Commands
### UI suite - full run
```powershell
$env:PYTHONPATH=(Resolve-Path .); .venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_ui_full_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').html
```

### UI suite - single step
```powershell
$env:PYTHONPATH=(Resolve-Path .); $env:CERT_TEST_STEP='5'; .venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_ui_report_single_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html
```
Set `CERT_TEST_STEP` to 1-17.

### UI suite - subset via -k
```powershell
# Steps 1-8
$env:PYTHONPATH=(Resolve-Path .); .venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py -k "step_01_login_as_admin or step_02_create_key or step_03_create_req_template or step_04_create_ext_template or step_05_create_csr or step_06_create_enrollment_policy_1d or step_07_create_challenge_password or step_08_sign_csr_with_policy" --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_ui_report_steps_1_to_8_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html

# Steps 9-17
$env:PYTHONPATH=(Resolve-Path .); .venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py -k "step_09_check_certificate_in_list or step_10_download_certificate or step_11_revoke_certificate or step_12_delete_certificate or step_13_delete_enrollment_policy or step_14_delete_challenge_password or step_15_delete_certificate_request_csr or step_16_delete_certificate_templates_req_ext or step_17_delete_key" --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_ui_report_steps_9_to_17_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html
```

### API suite - full run
```powershell
$env:PYTHONPATH=(Resolve-Path .); .venv\Scripts\pytest.exe tests_repo/test_certificates_api.py --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_api_full_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').html
```
Notes:
- Auto-generates a challenge password via API token (not UI)
- Attaches each PS1 stdout/stderr
- Waits 20s and cleans generated keys/certs/CSRs and DB rows matching test subjects

### API suite - targeted runs
```powershell
# Only mTLS EST
$env:PYTHONPATH=(Resolve-Path .); .venv\Scripts\pytest.exe tests_repo/test_certificates_api.py -k "estclient_go_mtls" --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_api_mtls_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html

# Only SCEP with challenge password
$env:PYTHONPATH=(Resolve-Path .); .venv\Scripts\pytest.exe tests_repo/test_certificates_api.py -k "sscep_with_challenge_password" --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_api_scep_pass_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html
```

## Reports
- Saved to `tests_repo/reports/` with timestamps.
- `--self-contained-html` keeps styling when you move the file; `--capture=tee-sys` shows stdout in terminal and embeds it in the report.
- Environment block includes local time (see `tests_repo/conftest.py`).
