# Security Reports

## Files
- bandit-report.json: Static analysis results from Bandit.
- bandit-report.html: Static HTML report from Bandit.
- bandit-report-interactive.html: HTML report with search, filter, and sort.
- pip-audit.txt: Dependency vulnerability report from pip-audit.
- pip-audit.html: HTML wrapper for pip-audit output.
- pip-audit.json: pip-audit JSON output (source for HTML view).
- pip-audit-interactive.html: HTML report with search, filter, sort, severity, and score.
- history/: Dated snapshots of the current reports.

## Bandit report sources
- Bandit scans `app.py` and its local Python imports only (repo-local modules).
- The file list is resolved by `skills/check-security/scripts/resolve_app_deps.py`, which parses imports and includes existing `.py` or package `__init__.py` files under the repo root.
- The scan command is driven by `skills/check-security/scripts/run_security.ps1`.
- Bandit does not query public vulnerability databases; it is static analysis of this codebase only.

## pip-audit sources
- `pip-audit` checks `requirements.txt` against public vulnerability advisories (known CVEs) for Python packages.
- Results are written to `security/pip-audit.txt` and `security/pip-audit.html`.
- HTML view is generated from `security/pip-audit.json` and enriches CVEs with NVD first, then GHSA, then OSV for severity/score when available.

## How to view
- Open `security/bandit-report-interactive.html` in your browser (search, filter, sort).
- Open `security/bandit-report.html` for the default Bandit HTML.
- Open `security/bandit-report.json` in your editor, or pretty-print it:
  `Get-Content security\bandit-report.json | ConvertFrom-Json | ConvertTo-Json -Depth 6`
- Open `security/pip-audit.txt` or `security/pip-audit.html`.
- Open `security/pip-audit-interactive.html` in your browser (search, filter, severity, score).
- History snapshots live under `security/history/YYYY-MM-DD_HH-mm-ss/`.
