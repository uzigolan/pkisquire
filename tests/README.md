# Test Scripts (Community Repo)

This directory contains protocol test scripts and helper code used by the PKI server.

## Edition behavior

- Community edition blocks enterprise protocol endpoints (SCEP/EST/OCSP) by design.
- Enterprise protocol tests and bundled protocol clients are maintained in the Enterprise repository (`pkisquire-ee`).

## Included here

- `tests/bin/` Python helper tools.
- `tests/scripts/` PowerShell test runners.

## Run from repo root

```powershell
$env:PYTHONPATH = (Resolve-Path .)
```

Examples:

```powershell
.\tests\scripts\test_basic.ps1
.\tests\scripts\test_pyscep.ps1
.\tests\scripts\test_ocsp.ps1
```

For full UI/API pytest suites and reports, see `tests_repo/README.md`.
