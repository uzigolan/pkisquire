# Pikachu CA Configuration Reference

This document describes all options available in `config.ini` for the Pikachu CA server.

---

## Edition Selection
- Runtime edition is controlled by environment variable `PIKACHU_EDITION`.
- Supported values: `community` (default), `enterprise`.
- This is not configured in `config.ini`.
- In `community`, enterprise-only routes/features are unavailable (return `404`).

Example:
```powershell
$env:PIKACHU_EDITION = "enterprise"
python app.py
```

---

## [DEFAULT]
- **SECRET_KEY**: Flask secret key for session security.
- **http_port**: HTTP port for unauthenticated OCSP (default: 80).
- **max_idle_time**: Maximum idle time before automatic logout (e.g., `10h`, `4d`, `20m`).
- **allow_self_registration**: Enable self-registration at `/users/register` (`true`/`false`).
- **show_legacy_paths**: Show legacy routes like `/x509_templates` (`true`/`false`). Requires admin role.
- **default_new_user_role**: Default role for newly onboarded users (`user` or `admin`). If missing or invalid, defaults to `user`.

## [LOGGING]
- **log_level**: Logging level (`TRACE`, `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).
- **log_file**: Path to the log file.

## [CA]
- **mode**: Which subordinate CA to use by default (`EC` or `RSA`).
- **SUBCA_KEY_PATH_EC**: Path to EC sub-CA private key.
- **SUBCA_CERT_PATH_EC**: Path to EC sub-CA certificate.
- **CHAIN_FILE_PATH_EC**: Path to EC chain file.
- **SUBCA_KEY_PATH_RSA**: Path to RSA sub-CA private key.
- **SUBCA_CERT_PATH_RSA**: Path to RSA sub-CA certificate.
- **CHAIN_FILE_PATH_RSA**: Path to RSA chain file.
- **ROOT_CERT_PATH**: Path to root CA certificate.

## [VAULT]
- **enabled**: Enable HashiCorp Vault integration (`true`/`false`).
- **address**: Vault server address (e.g., `http://127.0.0.1:8200`).
- **role_id**: Vault AppRole ID (usually set via environment variable).
- **secret_id**: Vault AppRole Secret ID (usually set via environment variable).
- **pki_rsa_path**: Vault PKI mount path for RSA.
- **pki_ec_path**: Vault PKI mount path for EC.
- **transit_path**: Vault transit engine path for custom signing.
- **timeout**: Vault connection timeout (seconds).
- **retry_attempts**: Number of retry attempts for Vault connection.
- **verify_ssl**: Verify Vault server SSL certificate (`true`/`false`).
- **ca_cert_path**: Path to CA certificate for Vault SSL verification.
- **role_scep**: Vault role for SCEP operations.
- **role_est**: Vault role for EST operations.
- **role_default**: Vault role for default operations.

## [LDAP]
- **LDAP_HOST**: LDAP server address.
- **LDAP_PORT**: LDAP server port.
- **BASE_DN**: Base DN for LDAP queries.
- **PEOPLE_DN**: DN for people/users in LDAP.
- **ADMIN_DN**: DN for LDAP admin user.
- **ADMIN_PASSWORD**: Password for LDAP admin user.
- **enabled**: Enable LDAP integration (`true`/`false`).

## [SCEP]
- **enabled**: Enable SCEP protocol (`true`/`false`).
- **serial_file**: Path to file for SCEP serial persistence.
- **dump_dir**: Directory for raw SCEP request dumps.
- **challenge_password_enabled**: Enable challenge-password feature (`true`/`false`).
- **challenge_password_validity**: Validity period for challenge-passwords (e.g., `60m`, `2m`).

## [OCSP]
- **hash_algorithm**: OCSP CertID hash algorithm (`sha1` or `sha256`). Use `sha1` for legacy client compatibility, `sha256` for stronger hashing.

## [HTTPS]
- **ssl_cert**: Path to HTTPS certificate.
- **ssl_key**: Path to HTTPS private key.
- **port**: HTTPS port (default: 443).

## [TRUSTED_HTTPS]
- **trusted_ssl_cert**: Path to trusted HTTPS certificate.
- **trusted_ssl_key**: Path to trusted HTTPS private key.
- **trusted_port**: Trusted HTTPS port (default: 4443).

## [PATHS]
- **crl_path**: Path to CRL file.
- **server_ext_cfg**: Path to server extension config file.
- **validity_conf**: Path to validity config file.
- **db_path**: Path to SQLite database file.

---

For any option not listed here, see comments in `config.ini` or ask for further details.
