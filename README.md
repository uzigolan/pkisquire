# 🔡 RAD PKI Certificate Authority Server

Welcome to the RAD CA Server — a Flask-based Public Key Infrastructure (PKI) platform designed for managing certificate lifecycles, securing MQTT brokers, and supporting quantum-safe key algorithms! Pika Pi! ⚡

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

* 📄 Web UI + RESTful API support
* 🔒 CSR submission and certificate issuance
* 📄 Certificate revocation and CRL generation
* 🌐 SCEP and EST protocol support for automated enrollment
* ⚛️ Post-Quantum Cryptography (e.g., Dilithium)
* 📡 MQTTs TLS integration
* ✅ OCSP real-time validation

---

## 🛠️ Installation

> **Requirements**: Rocky Linux 9.x, Python 3, Flask, OpenSSL, oqs-provider

### 1. Clone the repo and install dependencies:

```bash
sudo dnf install python3
pip install Flask cryptography asn1crypto
```

### 2. Extract and set up the server:

```bash
tar xvfz pki_server_1.tar.gz
cd pki-server
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

## 🌐 Web Access

Access the server via:

```
https://openxpki.iot-rad.com:4443/
```

---

## 📎 License

> This software is proprietary and confidential. Unauthorized use, copying, or distribution is strictly prohibited without prior written consent from RAD Data Communications Ltd.

---

## ⚡ Pikachu Says...

Stay secure, and may your certs never expire! Pika Pi! 💛

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
