# Certificate UI Test Suite

This folder contains the UI-focused certificate lifecycle tests run with pytest.

## Prerequisites
- Activate the virtualenv: `.\.venv\Scripts\activate`
- Ensure dependencies are installed: `pip install -r requirements.txt`
- Run from repo root so imports like `app` resolve (we set `PYTHONPATH=. in the command below).

## Run all 15 step tests with HTML report (captures stdout)
```powershell
$env:PYTHONPATH='.'; .venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py --html=tests_repo/reports/pikachu_test_report_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html --capture=tee-sys
```
- Generates a timestamped report in `tests_repo/reports/`.
- Each step is its own test (names like `step_01_login_as_admin` … `step_15_delete_key`).
- Output includes 5-second pauses between steps.

## Run a single step (prereqs are created first)
```powershell
$env:PYTHONPATH='.'; $env:CERT_TEST_STEP='5'; .venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py --html=tests_repo/reports/pikachu_test_report_single_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html --capture=tee-sys
```
- Set `CERT_TEST_STEP` to the desired step number (1–15).
- The test will run prerequisite steps in order before the target step, with the same 5s pauses.

## Run a subset of steps (no CERT_TEST_STEP needed)
```powershell
# Example: only steps 1–4
$env:PYTHONPATH='.'; .venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py -k "step_01_login_as_admin or step_02_create_key or step_03_create_req_template or step_04_create_ext_template" --html=tests_repo/reports/pikachu_test_report_steps_1_to_4_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html --capture=tee-sys

# Example: only steps 5–15
$env:PYTHONPATH='.'; .venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py -k "step_05_create_csr or step_06_create_enrollment_policy_1d or step_07_sign_csr_with_policy or step_08_check_certificate_in_list or step_09_download_certificate or step_10_revoke_certificate or step_11_delete_certificate or step_12_delete_enrollment_policy or step_13_delete_certificate_request_csr or step_14_delete_certificate_templates_req_ext or step_15_delete_key" --html=tests_repo/reports/pikachu_test_report_steps_5_to_15_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html --capture=tee-sys
```
- Adjust the `-k` expression to include the step ids you want.
- Tests not matched by `-k` will be deselected (shown as `deselected` in pytest output).

## Report contents
- Environment section includes local time.
- Each test row has captured stdout showing “Step X complete…” messages and pauses.
- A “steps” attachment lists step outcomes when using the `--capture=tee-sys` command above.
