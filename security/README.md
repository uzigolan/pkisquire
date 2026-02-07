# Security Reports

## Files
- bandit-report.json: Static analysis results from Bandit.
- bandit-report.html: Static HTML report from Bandit.
- bandit-report-interactive.html: Interactive HTML report (search, filter, sort).
- pip-audit.txt: Dependency vulnerability report from pip-audit.
- pip-audit.html: HTML wrapper for pip-audit output.
- history/: Dated snapshots of the current reports.

## How to view
- Open `security/bandit-report-interactive.html` in your browser.
- Open `security/bandit-report.html` for the default Bandit HTML.
- Open `security/bandit-report.json` in your editor, or pretty-print it:
  `Get-Content security\bandit-report.json | ConvertFrom-Json | ConvertTo-Json -Depth 6`
- Open `security/pip-audit.txt` or `security/pip-audit.html`.
- History snapshots live under `security/history/YYYY-MM-DD_HH-mm-ss/`.
