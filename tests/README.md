# SCEP & EST Testing Suite

This directory contains SCEP and EST client implementations and test scripts for the PKI CA server.

## Directory Structure

```
tests/
├── bin/                    # Python SCEP client tools
│   ├── scep_client.py     # Base SCEP client implementation
│   ├── scep_enroll.py     # SCEP enrollment client
│   └── scep_tool.py       # SCEP utility tool (GetCA, GetCaps)
│
├── estclient/              # EST client directory
│   ├── estclient.exe      # Go-based EST client (rebuilt with TLS insecure)
│   ├── estclient-go/      # Go source for EST client
│   └── *.crt, *.key       # EST test artifacts
│
├── results/                # Test output directory
│   ├── *.crt              # Certificate files
│   ├── *.key              # Private keys
│   ├── *.csr              # Certificate signing requests
│   ├── ocsp_request*.der  # OCSP request DER files
│   ├── ocsp_response*.der # OCSP response DER files
│   └── scep_response.bin  # Raw SCEP response (debugging)
│
├── scripts/                # PowerShell test scripts
│   ├── pyscep.ps1         # Python SCEP wrapper script
│   ├── test_pyscep.ps1    # Python SCEP test suite
│   ├── test_sscep.ps1     # Compiled sscep test suite
│   ├── test_estclient_curl.ps1  # EST client using curl (recommended)
│   ├── test_estclient_go.ps1    # EST client using estclient.exe
│   └── test_ocsp.ps1      # OCSP responder validation test
│
└── sscep/                  # Compiled sscep binary
    └── sscep.exe          # Native C SCEP client (certnanny/sscep 0.10.0)
```

## SCEP Clients

### 1. sscep (Compiled C Client)
- **Location**: `tests/sscep/sscep.exe`
- **Source**: https://github.com/certnanny/sscep v0.10.0
- **Build**: Static binary (4.5MB) with OpenSSL 3.6.0
- **Purpose**: Production-ready SCEP client for Windows
- **Supported Operations**:
  - `getcaps` - Query CA capabilities
  - `getca` - Download CA certificate
  - `enroll` - Certificate enrollment

### 2. Python SCEP Client
- **Location**: `tests/bin/`
- **Purpose**: Testing and debugging tool
- **Components**:
  - `scep_tool.py` - GetCA and GetCaps operations
  - `scep_enroll.py` - Full enrollment with PKCS#7 wrapping
  - `scep_client.py` - Base client functionality
- **Wrapper**: `tests/scripts/pyscep.ps1` for easy execution

## EST Clients

### 1. curl-based EST Client (Recommended)
- **Location**: `tests/scripts/test_estclient_curl.ps1`
- **Purpose**: Production-ready EST enrollment using native curl
- **Supported Operations**:
  - Get CA certificates (/.well-known/est/cacerts)
  - Simple enrollment (/.well-known/est/simpleenroll)
- **Features**:
  - EC prime256v1 key generation
  - DER format CSR submission
  - Base64 PKCS#7 response handling
  - Automatic certificate extraction and verification

### 2. Go EST Client (estclient.exe)
- **Location**: `tests/estclient/estclient.exe`
- **Source**: https://github.com/bl9/estclient-go (modified)
- **Modifications**: Added `-insecure` flag for TLS certificate skip
- **Purpose**: Alternative EST client for testing
- **Supported Operations**:
  - `cacerts` - Get CA certificates
  - `enroll` - Simple enrollment
  - `reenroll` - Re-enrollment
  - `csrattrs` - Get CSR attributes
- **Usage**: `estclient.exe -server https://localhost:443 -cmd cacerts -insecure`

## Test Suites

### Running Tests

All test suites must be run from the **workspace root directory**.

#### Test SCEP - sscep (Compiled Binary)
```powershell
.\tests\scripts\test_sscep.ps1
```

Tests all 3 core SCEP operations:
- ✅ GetCaps - Query server capabilities
- ✅ GetCA - Download CA certificate  
- ✅ Enroll - Certificate enrollment with AES/SHA256

#### Test SCEP - Python Client
```powershell
.\tests\scripts\test_pyscep.ps1
```

Tests Python implementation of SCEP protocol:
- ✅ GetCaps - Query server capabilities
- ✅ GetCA - Download CA certificate
- ✅ Enroll - Certificate enrollment

#### Test EST - curl Client (Recommended)
```powershell
.\tests\scripts\test_estclient_curl.ps1
```

Tests EST protocol using curl and OpenSSL:
- ✅ Get CA certificates (CACerts)
- ✅ Generate EC prime256v1 key
- ✅ Generate and submit CSR
- ✅ Simple enrollment
- ✅ Decode base64 PKCS#7 response
- ✅ Extract and verify certificate

#### Test EST - Go Client
```powershell
.\tests\scripts\test_estclient_go.ps1
```

Tests Go-based EST client executable:
- ✅ Generate EC key and CSR
- ✅ Execute estclient.exe with insecure TLS
- ✅ Verify EST operations work

#### Test OCSP Responder
```powershell
.\tests\scripts\test_ocsp.ps1
```

Tests OCSP responder validation:
- ✅ Test known certificate (enrolled from SCEP/EST)
  - Sends OCSP request for enrolled certificate
  - Verifies "good" status response
  - Validates response signature
- ✅ Test unknown certificate (self-signed)
  - Generates certificate not issued by CA
  - Verifies "unauthorized" status response
  - Confirms proper rejection of unknown certificates

### Test Output

All test artifacts are saved to their respective directories:

**SCEP sscep outputs** (`tests/results/`):
- `test.key` - Generated private key (2048-bit RSA)
- `test.csr` - Certificate signing request
- `ca.crt` - Downloaded CA certificate (1,521 bytes)
- `enrolled.crt` - Enrolled certificate (1,996 bytes)

**SCEP Python outputs** (`tests/results/`):
- `py_test.key` - Generated private key (2048-bit RSA)
- `py_test.csr` - Certificate signing request
- `py_ca.crt` - Downloaded CA certificate (1,521 bytes)
- `py_enrolled.crt` - Enrolled certificate (2,000 bytes)
- `scep_response.bin` - Raw SCEP server response (debugging)

**EST curl outputs** (`tests/estclient/`):
- `etx.key` - Generated EC prime256v1 private key
- `etx.csr` - Certificate signing request (PEM)
- `etx.csr.der` - Certificate signing request (DER)
- `chain.crt` - Downloaded CA certificate chain (2,262 bytes)
- `etx.crt.p7` - Enrolled certificate in PKCS#7 format (base64)
- `etx.crt.p7.der` - Decoded PKCS#7 (DER)
- `etx.crt` - Extracted certificate (PEM)

**EST Go outputs** (`tests/estclient/`):
- `etx-estclient.key` - Generated EC prime256v1 private key
- `etx-estclient.csr` - Certificate signing request

**OCSP outputs** (`tests/results/`):
- `ocsp_request.der` - OCSP request for known certificate (124 bytes)
- `ocsp_response.der` - OCSP response for known certificate (731 bytes)
- `ocsp_request_unknown.der` - OCSP request for unknown certificate (124 bytes)
- `ocsp_response_unknown.der` - OCSP response for unknown certificate (5 bytes)
- `unknown_cert.pem` - Self-signed certificate (not from CA)
- `unknown_key.pem` - Private key for unknown certificate

## Server Configuration

### SCEP Server
- **Endpoint**: http://localhost:8090/scep
- **CA Mode**: RSA (required for SCEP)
- **Supported Operations**: GetCACaps, GetCACert, PKIOperation (enrollment only)
- **Algorithms**:
  - Signature: SHA-256
  - Encryption: AES, 3DES
  - Hash: SHA-1, SHA-256, SHA-512

### EST Server
- **Endpoint**: https://localhost:443/.well-known/est/
- **CA Mode**: RSA or ECC (both supported)
- **Supported Operations**: cacerts, simpleenroll
- **Authentication**: None (anonymous enrollment allowed)
- **Response Format**: Base64-encoded PKCS#7 DER
- **TLS**: Self-signed certificate (use `-k` flag with curl)

### OCSP Responder
- **Endpoint**: http://localhost:80/ocsp
- **CA Mode**: RSA or ECC (both supported)
- **Supported Operations**: Certificate status checking (good, revoked, unknown)
- **Authentication**: None (anonymous queries allowed)
- **Request Format**: DER-encoded OCSP request
- **Response Format**: DER-encoded OCSP response
- **Response Types**:
  - `successful (0x0)` - Certificate status returned (good/revoked)
  - `unauthorized (0x6)` - Certificate not issued by this CA
- **Signature**: Signed by SubCA key
- **Validity**: 7 days (thisUpdate to nextUpdate)

## Protocol Details

### SCEP Protocol (RFC 8894)

#### Supported SCEP Operations

#### 1. GetCACaps
Query server capabilities to determine supported features.

**Request:**
```
GET /scep?operation=GetCACaps
```

**Response:**
```
POSTPKIOperation
SHA-1
SHA-256
AES
DES3
SHA-512
Renewal
```

#### 2. GetCACert
Download the CA certificate for enrollment.

**Request:**
```
GET /scep?operation=GetCACert
```

**Response:** CA certificate in DER format (PKCS#7 degenerate)

#### 3. PKIOperation (Enrollment)
Enroll a certificate by submitting a CSR wrapped in encrypted PKCS#7.

**Request:**
```
POST /scep?operation=PKIOperation
Content-Type: application/x-pki-message
Body: Encrypted PKCS#7 message containing CSR
```

**Response:** PKCS#7 SignedData containing the issued certificate

### Message Flow

1. **Client** → GetCACaps: Query server capabilities
2. **Server** → Returns: List of supported features
3. **Client** → GetCACert: Download CA certificate
4. **Server** → Returns: CA certificate in PKCS#7 format
5. **Client** → PKIOperation: Submit encrypted enrollment request
   - Create temporary self-signed certificate
   - Wrap CSR in PKCS#7
   - Encrypt with CA public key (AES)
   - Sign with temporary certificate
6. **Server** → Returns: Signed PKCS#7 containing issued certificate
7. **Client** → Verifies signature and extracts certificate

### EST Protocol (RFC 7030)

#### Supported EST Operations

##### 1. CACerts
Download CA certificate chain for trust establishment.

**Request:**
```
GET /.well-known/est/cacerts
```

**Response:** Base64-encoded PKCS#7 containing CA certificates

##### 2. SimpleEnroll
Enroll a certificate by submitting a CSR.

**Request:**
```
POST /.well-known/est/simpleenroll
Content-Type: application/pkcs10
Body: DER-encoded CSR
```

**Response:** Base64-encoded PKCS#7 SignedData containing the issued certificate

#### EST Message Flow

1. **Client** → CACerts: Download CA certificate chain
2. **Server** → Returns: PKCS#7 with CA certificates (base64)
3. **Client** → Decodes base64 and extracts CA certificate
4. **Client** → SimpleEnroll: Submit DER-encoded CSR
5. **Server** → Returns: PKCS#7 with issued certificate (base64)
6. **Client** → Decodes base64, extracts certificate from PKCS#7
7. **Client** → Verifies certificate with CA certificate

### OCSP Protocol (RFC 6960)

#### Supported OCSP Operations

##### Certificate Status Check
Query the revocation status of a certificate issued by the CA.

**Request:**
```
POST /ocsp
Content-Type: application/ocsp-request
Body: DER-encoded OCSP request
```

**OCSP Request Structure:**
- **Certificate ID**: SHA-1 hash of issuer name and key
- **Serial Number**: Certificate serial number to check
- **Hash Algorithm**: SHA-1 (for compatibility)

**Response:** DER-encoded OCSP response with signature

**OCSP Response Structure:**
- **Response Status**:
  - `successful (0x0)` - Response contains certificate status
  - `unauthorized (0x6)` - Certificate not recognized by this responder
- **Certificate Status** (if successful):
  - `good` - Certificate is valid and not revoked
  - `revoked` - Certificate has been revoked (with revocation time and reason)
  - `unknown` - Certificate status is unknown
- **Signature**: RSA-SHA256 signature from SubCA key
- **Validity Period**: 
  - `thisUpdate` - Current timestamp
  - `nextUpdate` - Current timestamp + 7 days

#### OCSP Message Flow

1. **Client** → POST /ocsp: Submit OCSP request with certificate serial
2. **Server** → Queries database for certificate status
3. **Server** → If certificate found:
   - Returns `successful` response with certificate status (good/revoked)
   - Includes signature from SubCA
   - Provides validity period (7 days)
4. **Server** → If certificate not found:
   - Returns `unauthorized` response (5 bytes)
   - Indicates certificate not issued by this CA
5. **Client** → Verifies OCSP response signature
6. **Client** → Checks validity period (thisUpdate/nextUpdate)
7. **Client** → Trusts certificate status

#### OCSP Test Scenarios

The test script validates two scenarios:

**Scenario 1: Known Certificate (Good Status)**
- Uses certificate enrolled via SCEP or EST
- Expected response: `successful (0x0)` with status `good`
- Response size: ~731 bytes (includes signature)
- Signature verification: Must pass with SubCA certificate

**Scenario 2: Unknown Certificate (Unauthorized)**
- Uses self-signed certificate not issued by CA
- Expected response: `unauthorized (0x6)`
- Response size: 5 bytes (minimal error response)
- Demonstrates proper rejection of unknown certificates

## Technical Notes

### SCEP Client Requirements
- **sscep**: Standalone binary, no dependencies
- **Python SCEP**: Python 3.12+ with virtual environment at workspace `/.venv`
  - Required packages: `cryptography`, `requests`, `asn1crypto`
  - Imports modules from workspace root via `sys.path`

### EST Client Requirements
- **curl EST**: Native Windows curl.exe (built-in) and OpenSSL
- **Go EST**: estclient.exe compiled from Go source
  - Modified to support `-insecure` flag for self-signed certificates
  - Default server: https://localhost:443

### Known Limitations
- **SCEP**: Signature verification fails (expected - uses temporary self-signed cert)
- **SCEP**: Python client is for debugging only; sscep is the production client
- **SCEP**: Server only supports 3 core operations (GetCert, GetCRL, GetNextCA removed)
- **EST**: Anonymous enrollment (no user authentication required)
- **EST**: Go client requires insecure TLS for localhost testing
- **OCSP**: No nonce support in responses (optional per RFC 6960)
- **OCSP**: Response validity is 7 days (configurable in server code)

### Certificate Subject Preservation
All clients (SCEP and EST) properly preserve the CSR subject in the enrolled certificate:
- Input CSR: `CN=test.example.com, OU=IT, O=TestOrg, ...`
- Output Cert: Same subject (no modification by server)

## Build Information

### sscep Compilation
If you need to rebuild sscep.exe:

**Prerequisites:**
- Visual Studio Build Tools 2022
- CMake 4.2.0+
- vcpkg package manager
- OpenSSL 3.6.0 (via vcpkg, x64-windows-static triplet)

**Build:**
```powershell
cd tests/sscep-source
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=../vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release
```

Binary output: `tests/sscep-source/build/Release/sscep.exe`

### EST Client Compilation
If you need to rebuild estclient.exe:

**Prerequisites:**
- Go 1.25.5+ (windows/amd64)
- Git to clone source repository

**Build:**
```powershell
# Clone repository (if not already present)
cd tests/estclient
git clone https://github.com/bl9/estclient-go

# Modify cmd/main.go to add insecure TLS support

# Build
cd estclient-go
go build -o ..\estclient.exe .\cmd\main.go
```

Binary output: `tests/estclient/estclient.exe`

**Modifications Made:**
- Added `-insecure` flag (default: true) to skip TLS certificate verification
- Added custom `getInsecure()` function for self-signed certificate support
- Preserved all original EST operations (cacerts, enroll, reenroll, csrattrs)

## Troubleshooting

### Server Not Running
Ensure the Flask server is running:
- **SCEP**: Port 8090 (HTTP)
- **EST**: Port 443 (HTTPS)

```powershell
.\scripts\restart_server_clear_log.ps1
```

### Python Import Errors
All Python scripts in `tests/bin/` add the workspace root to `sys.path` automatically. If imports fail, verify the virtual environment is activated.

### SCEP Enrollment Fails
1. Check that `config.ini` has `mode = RSA` (not ECC)
2. Verify CA certificate exists: `pki-subca/rad_ca_sub_rsa.crt`
3. Check server logs: `logs/server.log`

### EST Enrollment Fails
1. Verify server is running on port 443 (HTTPS)
2. Check EST endpoint is enabled in app.py
3. Use `-k` flag with curl for self-signed certificates
4. Check server logs: `logs/server.log`

### EST PKCS#7 Decode Error
The server returns base64-encoded PKCS#7. Ensure you decode it before extraction:
```powershell
openssl base64 -d -in response.p7 -out response.der
openssl pkcs7 -inform DER -in response.der -print_certs -out cert.pem
```

### OCSP Test Prerequisites
The OCSP test requires an enrolled certificate from SCEP or EST tests. Run one of these first:
```powershell
.\tests\scripts\test_sscep.ps1      # Creates tests/results/enrolled.crt
.\tests\scripts\test_pyscep.ps1     # Creates tests/results/py_enrolled.crt
.\tests\scripts\test_estclient_curl.ps1  # Creates tests/estclient/etx.crt
```

### OCSP Response Errors
If OCSP returns 404 or wrong port error:
1. Verify server is running on port 80 (HTTP default)
2. Check endpoint: `http://localhost:80/ocsp` (not 8090)
3. OCSP is on main Flask app port, not SCEP port
4. Check server logs: `logs/server.log`

### OCSP Unauthorized Response
The `unauthorized (0x6)` response is expected and correct when testing with unknown certificates. This confirms the OCSP responder properly rejects certificates not issued by the CA.

### Test Files Cleanup
To clean up test artifacts:
```powershell
Remove-Item tests/results/* -ErrorAction SilentlyContinue
Remove-Item tests/estclient/*.crt, tests/estclient/*.key, tests/estclient/*.csr, tests/estclient/*.p7* -ErrorAction SilentlyContinue
```

## Summary

This test suite provides comprehensive validation of:
- ✅ **SCEP Protocol**: Certificate enrollment via compiled C and Python clients
- ✅ **EST Protocol**: Certificate enrollment via curl and Go clients  
- ✅ **OCSP Protocol**: Certificate status validation with known and unknown certificates

All protocols support anonymous operations (no authentication required) for testing and automated enrollment scenarios.

---

## SCEP Challenge Password Support (Testing)

- If `challenge_password_enabled = true` in `config.ini`, SCEP enrollment requires a valid, unconsumed challenge password generated via the CA web UI.
- The test scripts `test_sscep.ps1` and `test_pyscep.ps1` will automatically skip execution if challenge password support is enabled, since they do not embed or manage challenge passwords.
- To test SCEP enrollment with challenge passwords, use the web UI to generate a password, embed it in your CSR, and run the enrollment manually or with a custom script.
- If `challenge_password_enabled = false`, the test scripts will run all SCEP operations as usual.
- EST and OCSP tests are not affected by the challenge password setting.

---
