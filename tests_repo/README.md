# Certificate Test Suites (UI & API)

Two pytest suites live here:
- `test_certificates_ui.py`: 15-step UI-style certificate lifecycle with 5s pauses between steps.
- `test_certificates_api.py`: API/PowerShell flows (basic endpoints, EST, EST mTLS, SCEP, SCEP with challenge) plus artifact/DB cleanup.

## Quick start
- Activate venv: `.\.venv\Scripts\activate`
- Install deps: `pip install -r requirements.txt`
- Always run from repo root and set PYTHONPATH: `$env:PYTHONPATH = (Resolve-Path .)`
- API extras:
  - `estclient` installed in WSL (default `~/go/bin/estclient`)
  - WSL `/etc/hosts` maps `localhost-wsl-win` to your Windows IP
  - `config.ini` has valid CA chain and trusted cert/key paths

## UI suite
- Full run (self-contained HTML, minute timestamp, prefix `pikachu_test_ui_full`):
  ```powershell
  $env:PYTHONPATH=(Resolve-Path .); .venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_ui_full_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').html
  ```
- Single step (auto-runs prereqs; prefix `pikachu_test_ui_report_single`):
  ```powershell
  $env:PYTHONPATH=(Resolve-Path .); $env:CERT_TEST_STEP='5'; .venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_ui_report_single_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html
  ```
  Set `CERT_TEST_STEP` to 1–15.
- Subset via `-k` (self-contained HTML):
  ```powershell
  # Steps 1–4
  $env:PYTHONPATH=(Resolve-Path .); .venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py -k "step_01_login_as_admin or step_02_create_key or step_03_create_req_template or step_04_create_ext_template" --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_ui_report_steps_1_to_4_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html
  # Steps 5–15
  $env:PYTHONPATH=(Resolve-Path .); .venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py -k "step_05_create_csr or step_06_create_enrollment_policy_1d or step_07_sign_csr_with_policy or step_08_check_certificate_in_list or step_09_download_certificate or step_10_revoke_certificate or step_11_delete_certificate or step_12_delete_enrollment_policy or step_13_delete_certificate_request_csr or step_14_delete_certificate_templates_req_ext or step_15_delete_key" --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_ui_report_steps_5_to_15_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html
  ```

## API suite
- Full run (self-contained HTML, minute timestamp):
  ```powershell
  $env:PYTHONPATH=(Resolve-Path .); .venv\Scripts\pytest.exe tests_repo/test_certificates_api.py --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_api_full_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').html
  ```
  Runs: basic endpoints, EST, EST mTLS, SCEP (skipped if challenge-only), SCEP with challenge. Auto-generates a challenge password (admin/pikachu), attaches each PS1 stdout/stderr, then waits 20s and cleans generated keys/certs/CSRs and DB rows matching test subjects.
- Common targeted runs:
  - Only mTLS EST:
    ```powershell
    $env:PYTHONPATH=(Resolve-Path .); .venv\Scripts\pytest.exe tests_repo/test_certificates_api.py -k "estclient_go_mtls" --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_api_mtls_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html
    ```
  - Only SCEP with challenge password:
    ```powershell
    $env:PYTHONPATH=(Resolve-Path .); .venv\Scripts\pytest.exe tests_repo/test_certificates_api.py -k "sscep_with_challenge_password" --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_api_scep_pass_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html
    ```

## Reports
- Saved to `tests_repo/reports/` with timestamps.
- `--self-contained-html` keeps styling when you move the file; `--capture=tee-sys` shows stdout in terminal and embeds it in the report.
- Environment block includes local time (see `tests_repo/conftest.py`).
