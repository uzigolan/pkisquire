# 🔐 Pikachu CA - PKI Certificate Authority Server

A Flask-based Public Key Infrastructure (PKI) platform for managing certificate lifecycles with SCEP, EST, and OCSP protocol support.

**GitHub Repository**: [https://github.com/uzigolan/pikachu-ca](https://github.com/uzigolan/pikachu-ca)

---

## 🔍 Overview

This server provides tools for:

* Generating RSA, ECC, and quantum-safe keys
* Submitting and signing Certificate Signing Requests (CSR)
* Managing issued certificates (view, revoke, delete)
* Downloading CA chains and Certificate Revocation Lists (CRLs)
* Real-time certificate validation via OCSP
* Automated device enrollment via SCEP and EST protocols
* TLS authentication for MQTT with CRL enforcement

---

## 🚀 Features

* 📄 **Web UI + RESTful API** - Intuitive interface with programmatic access
* 🔒 **CSR submission and certificate issuance** - Full certificate lifecycle management
* 📄 **Certificate revocation and CRL generation** - Automated revocation lists
* 🌐 **SCEP and EST protocol support** - Automated device enrollment
* ⚛️ **Post-Quantum Cryptography** - Support for quantum-safe algorithms (e.g., Dilithium)
* 📡 **MQTTs TLS integration** - Secure MQTT with certificate authentication
* ✅ **OCSP real-time validation** - Instant certificate status verification
* 🏢 **Multi-tenancy support** - User isolation and role-based access control
* 🔐 **HashiCorp Vault integration** - Optional CA key isolation and secure signing
  - Private keys stored in Vault (never on filesystem)
  - Signing operations performed via Vault PKI engine
  - Support for dual CA modes (RSA and EC) with separate Vault engines
  - Automatic fallback to legacy file-based keys if Vault unavailable
  - AppRole authentication with configurable policies
  - **Vault is supported only for Web UI and EST enrollment. SCEP protocol does NOT support Vault and always uses local file-based keys.**

---

## 🛠️ Installation

> **Requirements**: Rocky Linux 9.x, Python 3, Flask, OpenSSL, oqs-provider

### 1. Clone the repo and install dependencies:

```bash
git clone https://github.com/uzigolan/pikachu-ca.git
cd pikachu-ca
pip install Flask cryptography asn1crypto
```

### 2. Run the server:

```bash
python app.py
```

### 3. (Optional) Enable Quantum-Safe provider:

```bash
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
./scripts/fullbuild.sh
sudo cmake --install _build
```

---

## 🔐 HashiCorp Vault Integration

Pikachu CA supports **optional HashiCorp Vault integration** for enhanced security through CA key isolation.

> **Important:** Vault integration is only available for certificate signing via the Web UI and EST protocol. SCEP protocol does **not** support Vault and always uses local file-based CA keys due to protocol requirements for direct private key access.

### Benefits

* **Key Isolation** - Private CA keys never stored on filesystem or in memory
* **Secure Signing** - All certificate signing operations performed via Vault API
* **Audit Logging** - Vault logs all key access and signing operations
* **Access Control** - Fine-grained permissions via Vault policies
* **Dual CA Support** - Separate Vault PKI engines for RSA and EC certificates
* **Automatic Fallback** - Server continues with file-based keys if Vault unavailable

### Quick Setup

**1. Enable Vault in `config.ini`:**
```ini
[VAULT]
enabled = true
address = http://127.0.0.1:8200
pki_rsa_path = pki-subca-rsa
pki_ec_path = pki-subca-ec
```

**2. Start Vault server:**
```bash
# Development mode (for testing)
vault server -dev

# Production: Configure Vault with proper TLS and authentication
```

**3. Start PKI server with Vault support:**
```powershell
# Windows - Automatically configures Vault credentials
.\scripts\restart_server_clear_log.ps1

# Linux/Unix - Set environment variables manually
export VAULT_ROLE_ID="<your-role-id>"
export VAULT_SECRET_ID="<your-secret-id>"
export VAULT_ADDR="http://127.0.0.1:8200"
python app.py
```

**4. Verify Vault mode:**
```bash
# Check server logs
tail -f logs/server.log | grep -i vault

# Expected output:
# INFO [app] Vault integration is ENABLED
# INFO [vault_client] Authenticated with Vault at http://127.0.0.1:8200
# INFO [app] Running in VAULT MODE - keys isolated in Vault
```

### Architecture

```
┌──────────────────┐         ┌─────────────────────┐
│   Flask Server   │────────▶│  HashiCorp Vault    │
│   (Pikachu CA)   │ AppRole │                     │
│                  │  Auth   │  ┌───────────────┐  │
│  - Web UI        │◀────────│  │ pki-subca-rsa │  │
│  - SCEP/EST      │  Sign   │  │  (RSA keys)   │  │
│  - OCSP          │  CSR    │  └───────────────┘  │
│                  │         │  ┌───────────────┐  │
└──────────────────┘         │  │ pki-subca-ec  │  │
                             │  │  (EC keys)    │  │
                             └─────────────────────┘
```

### Switching Between RSA and EC Modes

```ini
# In config.ini
[CA]
mode = EC    # or "RSA"
```

When Vault is enabled:
- **RSA mode** → Uses `pki-subca-rsa` Vault engine
- **EC mode** → Uses `pki-subca-ec` Vault engine

### Documentation

For complete Vault setup, credential configuration, and troubleshooting, see:
- **[scripts/README.md](scripts/README.md)** - Server management with Vault integration
- **[scripts/VAULT_SCRIPTS_README.md](scripts/VAULT_SCRIPTS_README.md)** - Vault migration and setup scripts

---

## 🔑 SCEP Challenge Password Support

Pikachu CA supports one-time challenge passwords for SCEP certificate enrollment. This feature is controlled by the `challenge_password_enabled` setting in the `[SCEP]` section of `config.ini`.

- **When enabled (`challenge_password_enabled = true`)**:
  - Only CSRs containing a valid, unconsumed challenge password (generated via the web UI) will be accepted for certificate issuance.
  - Each challenge password can be used only once. After use, its status is marked as "Consumed" and it cannot be reused.
  - The list of available challenge passwords is stored in server memory and is cleared on server restart.
  - Attempts to use a missing, expired, or already consumed password will be rejected.
  - This feature applies **only to SCEP**. EST and other protocols are not affected.

- **When disabled (`challenge_password_enabled = false`)**:
  - SCEP enrollment does not require a challenge password.

**Note:**
- Challenge password support is implemented entirely in-memory for simplicity. For persistent tracking, consider extending the implementation to use a database.
- See `/challenge_passwords` in the web UI to generate and monitor challenge passwords.

---

## 🔗 Related Projects

- **SCEP Client**: [sscep](https://github.com/certnanny/sscep) - Simple SCEP client for automated enrollment
- **EST Client**: [estclient](https://github.com/globalsign/est) - GlobalSign EST protocol implementation
- **Post-Quantum Crypto**: [oqs-provider](https://github.com/open-quantum-safe/oqs-provider) - OpenSSL provider for quantum-safe algorithms

---

## 👤 User Management

- Supports multi-user accounts with roles: admin and user.
- Admins can approve, deactivate, activate, and manage users via the web UI.
- Each certificate, key, and profile is associated with a user (ownership enforced).
- Only admins can manage all resources; users can only view/manage their own.
- User status (active, deactivated, pending) is enforced at login and visible in the admin UI.
- Registration, login, and logout are available from the web interface.

---

## 🗄️ Database Initialization & Migration

### Initialize a New Database

To create a new database with all required tables and a default admin user:

```bash
python init_db.py
```

- Reads configuration from `config.ini` (including admin user credentials).
- Creates all tables and the initial admin user if not present.

### Migrate an Existing Database

To migrate an old database (e.g., certs.db) to the latest schema, including user table and admin user:

```bash
python migrate_db.py
```

- Adds missing columns (e.g., user_id) to existing tables if needed.
- Creates the users table and admin user if missing.
- Safe to run multiple times (idempotent).

---

## 🧪 Testing SCEP & EST Protocols

The server includes comprehensive test suites for SCEP (RFC 8894), EST (RFC 7030), and OCSP protocols.

### Test Directory Structure

```
tests/
├── scripts/               # PowerShell test scripts
│   ├── test_sscep.ps1    # SCEP test (compiled sscep client)
│   ├── test_pyscep.ps1   # SCEP test (Python implementation)
│   ├── test_estclient_curl.ps1  # EST test (curl-based, recommended)
│   ├── test_estclient_go.ps1    # EST test (Go executable)
│   └── test_ocsp.ps1     # OCSP validation test
├── sscep/                 # SCEP client binaries
├── estclient/             # EST client binaries and source
├── results/               # Test output (certificates, keys, OCSP responses)
└── README.md              # Detailed testing documentation
```

### Running Tests

All tests must be run from the workspace root directory:

#### SCEP Protocol Tests
```powershell
# Test with compiled sscep client (production-ready)
.\tests\scripts\test_sscep.ps1

# Test with Python SCEP implementation (debugging)
.\tests\scripts\test_pyscep.ps1
```

**SCEP Operations Tested:**
- ✅ GetCACaps - Query CA capabilities
- ✅ GetCACert - Download CA certificate
- ✅ Enroll - Certificate enrollment with PKCS#7 wrapping

**SCEP Endpoint:** `http://localhost:8090/scep`

#### EST Protocol Tests
```powershell
# Test with curl (recommended, production-ready)
.\tests\scripts\test_estclient_curl.ps1

# Test with Go EST client (alternative)
.\tests\scripts\test_estclient_go.ps1
```

**EST Operations Tested:**
- ✅ CACerts - Download CA certificate chain
- ✅ SimpleEnroll - Certificate enrollment with DER CSR

**EST Endpoint:** `https://localhost:443/.well-known/est/`

#### OCSP Protocol Tests
```powershell
# Test OCSP responder with both known and unknown certificates
.\tests\scripts\test_ocsp.ps1
```

**OCSP Operations Tested:**
- ✅ Known Certificate - Status validation (good/revoked) with signature verification
- ✅ Unknown Certificate - Proper rejection with "unauthorized" response
- ✅ Response signature verification with SubCA certificate

**OCSP Endpoint:** `http://localhost:80/ocsp`

**Manual OCSP Testing:**
```powershell
# Query OCSP status for a specific certificate
openssl ocsp \
  -reqout ocsp_request.der \
  -issuer pki-subca/rad_ca_sub_rsa.crt \
  -cert <path_to_certificate> \
  -url http://localhost:80/ocsp \
  -resp_text \
  -respout ocsp_response.der
```

### Test Requirements

- **SCEP**: Server running on port 8090 (HTTP), CA mode must be RSA
- **EST**: Server running on port 443 (HTTPS), supports both RSA and ECC
- **OCSP**: Server running on port 80 (HTTP), requires enrolled certificate from SCEP/EST tests
- **Clients**: 
  - sscep.exe (Windows binary included)
  - curl.exe (Windows built-in)
  - OpenSSL (for key/CSR generation and OCSP validation)
  - Python 3.12+ with virtual environment (for Python tests)
  - Go 1.25+ (for building EST client from source)

### Test Outputs

All test artifacts are saved to `tests/results/` and `tests/estclient/`:

- **Certificates**: `*.crt` (enrolled certificates from SCEP/EST)
- **Private Keys**: `*.key` (RSA 2048-bit and EC prime256v1)
- **CSRs**: `*.csr` (certificate signing requests)
- **OCSP Files**: `ocsp_request*.der`, `ocsp_response*.der`
- **PKCS#7**: `*.p7` (SCEP/EST responses)

### Documentation

For detailed information about test clients, protocol flows, troubleshooting, and build instructions, see:

```
tests/README.md
```

For more API examples including OCSP, SCEP, EST, and REST endpoints, visit the web UI at:

```
https://localhost:443/api
```

---
