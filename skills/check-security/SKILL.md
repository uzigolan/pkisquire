---
name: check-security
description: Run security scanning for this repo using Bandit and pip-audit, generate JSON/HTML/interactive reports under security/, and snapshot them under security/history. Use when asked to check vulnerabilities, produce security reports, or refresh security history snapshots.
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
3. Copy all reports into `security/history/YYYY-MM-DD_HH-mm-ss/`.

## Notes

- Requires `.venv` at repo root. The script installs `bandit` and `pip-audit` into the venv if missing.
- Update `security/README.md` manually only if the output set changes.

## Resources

### scripts/
- `run_security.ps1`: Run Bandit + pip-audit, generate reports, and snapshot into history.
- `make_bandit_interactive.py`: Build the interactive HTML view from the Bandit JSON report.
