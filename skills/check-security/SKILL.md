---
name: check-security
description: Run security scanning for this repo using Bandit, pip-audit, pip-licenses, and OpenSSL runtime capture; generate JSON/HTML/interactive reports under security/, and snapshot them under security/history. Use when asked to check vulnerabilities/licenses, produce security reports, or refresh security history snapshots.
---

# Check Security

## Overview

Generate security reports for this repo and keep a dated history snapshot of each run.

## Quick Start

Run the bundled script from the repo root:

```powershell
.\skills\check-security\scripts\run_security.ps1
```

## What It Does

1. Run Bandit on `app.py` and its local imports and write:
   - `security/bandit-report.json`
   - `security/bandit-report.html`
   - `security/bandit-report-interactive.html`
2. Run pip-audit and write:
   - `security/pip-audit.txt`
   - `security/pip-audit.html`
   - `security/pip-audit.json`
   - `security/pip-audit-interactive.html`
   - Interactive report includes `Published` (`YYYY-MM-DD HH:MM`), rows with `Severity=None` for packages with no known vulnerabilities, and OpenSSL package vulnerability rows from NVD when available.
3. Run pip-licenses and write:
   - `security/pip-licenses.txt`
   - `security/pip-licenses.html`
   - `security/pip-licenses.json`
   - `security/pip-licenses-interactive.html`
4. Apply license denylist policy from `security/license-denylist.txt` and write:
   - `security/pip-licenses-denied.txt`
5. Capture OpenSSL runtime details and write:
   - `security/openssl-info.txt`
6. Copy all reports into `security/history/YYYY-MM-DD_HH-mm-ss/`.

## Notes

- Requires `.venv` at repo root. The script installs `bandit`, `pip-audit`, and `pip-licenses` into the venv if missing.
- By default, denylist violations fail the run. Use `-NoLicensePolicyFail` to keep generating reports without failing.
- Update `security/README.md` manually only if the output set changes.
- App route `/security/openssl-info` shows OpenSSL runtime info captured at app startup (separate from the per-run `security/openssl-info.txt` report artifact).

## Resources

### scripts/
- `run_security.ps1`: Run Bandit + pip-audit + pip-licenses, generate reports, and snapshot into history.
- `make_bandit_interactive.py`: Build the interactive HTML view from the Bandit JSON report.
- `make_pip_audit_interactive.py`: Build the interactive HTML view from the pip-audit JSON report.
- `make_pip_licenses_interactive.py`: Build the interactive HTML view from the pip-licenses JSON report.
