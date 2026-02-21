# PKISquire CA - Community Edition

Flask-based PKI service for issuing, managing, and validating certificates with SCEP, EST, and OCSP support.

**GitHub:** https://github.com/uzigolan/pkisquire

---

## Overview

PKISquire CA provides certificate lifecycle management for devices and services:
- Generate RSA, ECC, and optional post-quantum keys
- Submit and sign CSRs via UI or API
- Revoke certificates and publish CRLs
- Validate status with OCSP
- Automate enrollment with SCEP and EST
- TLS authentication for MQTT with CRL enforcement

Note: any keys, certificates, and PKI artifacts included in this repository are for example/testing purposes only and must not be used in production.

## Licensing

- This repository is the **Community Edition** and is open source under `LICENSE.md` (MIT OR Apache-2.0).
- Enterprise features are distributed separately in `pkisquire-ee` under a commercial proprietary license.
- The Community Edition license does not grant rights to Enterprise Edition code.

## Enterprise Access

pkisquire-ee is private and available under a commercial license.

To request access, contact via GitHub profile: https://github.com/uzigolan
(or open an issue titled `Enterprise Access Request`) and include:
- Company name
- Use case
- Expected deployment size
- Timeline
## Editions

PKISquire CA supports two runtime editions controlled by `PIKACHU_EDITION`.

- `community` (default): core CA UI/API features.
- `enterprise`: enables enterprise protocol and security modules.

Set edition before starting the server:

```powershell
$env:PIKACHU_EDITION = "community"   # or "enterprise"
python app.py
```

Enterprise-only features include:
- EST (`/.well-known/est/*`)
- SCEP (`/scep`, `/cgi-bin/pkiclient.exe`)
- OCSP responder endpoints (`/ocsp`, `/ocspv`)
- Challenge password workflows
- User API tokens
- LDAP auth integration
- HashiCorp Vault integration
- PQC key generation from UI (`/generate` -> `PQC`) when `oqs-provider` is installed
- Code vulnerabilities reports (`/security/bandit-report-interactive`, `/security/pip-audit-interactive`, `/security/pip-licenses-interactive`)

### Feature Matrix

| Feature | Community | Enterprise |
| --- | --- | --- |
| Web UI + core REST API | Yes | Yes |
| Certificates (`/certs`) | Yes | Yes |
| RA Sign (`/sign`) | Yes | Yes |
| CSRs (`/requests`) | Yes | Yes |
| Keys (`/keys`) | Yes | Yes |
| Enrollment Policies (`/ra_policies`) | Yes | Yes |
| Certificate Templates (`/profiles`) | Yes | Yes |
| VA/CRL (`/va`) | Yes | Yes |
| CA management (`/ca`) | Yes | Yes |
| Events (`/events`) | Yes | Yes |
| Inspect (`/inspect`) | Yes | Yes |
| Logs (`/logs`) | Yes | Yes |
| User management (`/users/manage`, admin) | Yes | Yes |
| Certificate issuance/revocation/CRL | Yes | Yes |
| Automated tests (UI/API reports) | Yes | Yes |
| HashiCorp Vault integration | No | Yes |
| Multi-tenant RBAC | Yes | Yes |
| SCEP enrollment | No | Yes |
| EST enrollment | No | Yes |
| OCSP responder endpoints (`/ocsp`, `/ocspv`) | No | Yes |
| Challenge password workflows | No | Yes |
| User API tokens | No | Yes |
| LDAP authentication | No | Yes |
| PQC key generation in UI (`PQC`) | No | Yes |
| Code vulnerabilities reports | No | Yes |

---

## Features

- **Web UI + REST API** for day-to-day certificate operations
- **Issuance & revocation** with automated CRL generation
- **Protocol support:** SCEP and EST enrollment; OCSP validation
- **HashiCorp Vault integration** for CA key isolation and signing
- **Post-Quantum ready** (e.g., Dilithium via oqs-provider)
- **MQTT/TLS integration** for client-authenticated messaging
- **Multi-tenant RBAC** with user ownership and admin controls

---

## Quick Start

> Requirements: Rocky Linux 9.x, Python 3, Flask, OpenSSL, optional oqs-provider

```bash
git clone https://github.com/uzigolan/pkisquire-ca.git
cd pkisquire-ca
pip install -r requirements.txt
python app.py
```

To enable post-quantum algorithms, build and install `oqs-provider`:
```bash
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
./scripts/fullbuild.sh
sudo cmake --install _build
```

---

## Configuration

All settings live in `config.ini`. Key sections:
- `[DEFAULT]` session key, idle timeout
- `[LOGGING]` level and log file path
- `[CA]` RSA/EC mode, key and chain paths, root cert path
- `[VAULT]` enablement, address, AppRole creds, PKI mount paths
- `[LDAP]` directory settings and credentials
- `[SCEP]` enablement, data paths, challenge password options
- `[HTTPS]` and `[TRUSTED_HTTPS]` certificate, key, and port settings
- `[PATHS]` CRL, extension config, validity config, database path

For the full matrix of options, see `README_CONFIG.md`.

---

## HashiCorp Vault Integration

Vault support isolates CA keys and performs signing through Vault PKI engines. SCEP always uses local file-based keys; Vault is available for the Web UI and EST.

**Enable Vault in `config.ini`:**
```ini
[VAULT]
enabled = true
address = http://127.0.0.1:8200
pki_rsa_path = pki-subca-rsa
pki_ec_path = pki-subca-ec
```

**Run with Vault enabled:**
```powershell
# Windows: auto-configures Vault credentials
.\scripts\restart_server_clear_log.ps1

# Linux/macOS: set env vars then start the app
export VAULT_ROLE_ID="<role-id>"
export VAULT_SECRET_ID="<secret-id>"
export VAULT_ADDR="http://127.0.0.1:8200"
python app.py
```

Check `logs/server.log` for `Vault integration is ENABLED` to confirm.

---

## SCEP Challenge Passwords

When `[SCEP] challenge_password_enabled = true`:
- Only CSRs with a valid, unused challenge password are accepted
- Each password is single-use and persisted in the database
- Missing, expired, or consumed passwords are rejected

Generate and monitor challenge passwords at `/challenge_passwords` in the web UI. EST and other protocols are unaffected.

---

## Database Initialization and Migration

Create or migrate the database (idempotent):
```bash
python migrate_db.py
```
- Reads `config.ini` for connection info and admin credentials
- Creates required tables and the default admin user if missing
- Adds new columns (e.g., `user_id`) when needed

---

## Testing

Tests live under `tests/` and should be run from the repo root.

**Community repo examples:**
```powershell
.\tests\scripts\test_basic.ps1
.\tests\scripts\test_pyscep.ps1     # Python implementation
.\tests\scripts\test_estclient_curl.ps1   # curl-based checks
.\tests\scripts\test_ocsp.ps1
```

Enterprise protocol assets and full enterprise validation flows are maintained in `pkisquire-ee`.
For detailed local test notes, see `tests/README.md` and `tests_repo/README.md`.

---

## User Management

- Roles: admin and user
- Admins can activate, deactivate, and manage users and their resources
- Users see and manage only their own certificates, keys, and profiles
- Registration, login, and logout are available in the web UI

---

## Related Projects

- SCEP client: https://github.com/certnanny/sscep
- EST client: https://github.com/globalsign/est
- Post-Quantum crypto: https://github.com/open-quantum-safe/oqs-provider

---

## Additional Documentation

- `README_CONFIG.md` for configuration details
- `scripts/README.md` and `scripts/VAULT_SCRIPTS_README.md` for Vault setup and server management

---

## License

This project is dual-licensed under your choice of the MIT License or the Apache License, Version 2.0.
See `LICENSE.md` for full text.










