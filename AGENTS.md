# Guide for Future Agents

## Project Snapshot
- Flask-based PKI CA server (`app.py`) with SCEP, EST, OCSP, MQTT/TLS, and optional HashiCorp Vault key isolation.
- Configuration is driven by `config.ini`; detailed options live in `README_CONFIG.md`.
- Scripts for Vault/server management sit under `scripts/`; protocol test assets live in `tests/` and `tests_repo/`.

## Setup & Run
- Use Python 3; install deps from the repo root: `pip install -r requirements.txt` (activate `.venv` if present).
- Start the server from root: `python app.py` (uses `config.ini`, writes logs under `logs/`).
- Database bootstrap/migration: `python migrate_db.py` (idempotent) or `scripts/migrate_db.ps1`.
- Optional Vault mode: enable in `config.ini` and see `scripts/README.md` + `scripts/VAULT_SCRIPTS_README.md` for `start_vault.ps1`, `init_vault_pki.ps1`, and restart helpers.

## Tests (run from repo root)
- Protocol scripts (PowerShell): `tests/scripts/test_sscep.ps1`, `tests/scripts/test_pyscep.ps1`, `tests/scripts/test_estclient_curl.ps1`, `tests/scripts/test_estclient_go.ps1`, `tests/scripts/test_ocsp.ps1`.
- Pytest UI/API suites in `tests_repo/` (ensure venv active, set `PYTHONPATH=(Resolve-Path .)`):
  - Full UI flow: `.venv\Scripts\pytest.exe tests_repo/test_certificates_ui.py --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_ui_full_<timestamp>.html`
  - Full API flow: `.venv\Scripts\pytest.exe tests_repo/test_certificates_api.py --capture=tee-sys --self-contained-html --html=tests_repo/reports/pikachu_test_api_full_<timestamp>.html`
  - Targeted examples: `-k "estclient_go_mtls"` or `-k "sscep_with_challenge_password"`.
  - UI single step: set `CERT_TEST_STEP` env var and run the UI suite.
- Test artifacts land in `tests/results/`, `tests/estclient/`, and `tests_repo/reports/`.

## Conventions & Notes
- Work from the repo root to avoid path issues; PowerShell commands assume that location.
- Keep outputs ASCII-only; prior docs had encoding noise—avoid reintroducing it.
- Major config files: `config.ini`, `README_CONFIG.md`; main code in `app.py` and supporting modules in root (`ca.py`, `vault_client.py`, `x509_*`).
- If adjusting Vault or protocol behavior, also sync any relevant test scripts and `tests_repo/README.md`.
