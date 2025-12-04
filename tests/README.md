# SCEP Testing Suite

This directory contains all SCEP client implementations and test scripts for the PKI CA server.

## Directory Structure

```
tests/
├── bin/                    # Python SCEP client tools
│   ├── scep_client.py     # Base SCEP client implementation
│   ├── scep_enroll.py     # SCEP enrollment client
│   └── scep_tool.py       # SCEP utility tool (GetCA, GetCaps)
│
├── results/                # Test output directory
│   ├── *.crt              # Certificate files
│   ├── *.key              # Private keys
│   ├── *.csr              # Certificate signing requests
│   └── scep_response.bin  # Raw SCEP response (debugging)
│
├── scripts/                # PowerShell test scripts
│   ├── pyscep.ps1         # Python SCEP wrapper script
│   ├── test_pyscep.ps1    # Python SCEP test suite
│   └── test_sscep.ps1     # Compiled sscep test suite
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

## Test Suites

### Running Tests

Both test suites must be run from the **workspace root directory**.

#### Test sscep (Compiled Binary)
```powershell
.\tests\scripts\test_sscep.ps1
```

Tests all 3 core SCEP operations:
- ✅ GetCaps - Query server capabilities
- ✅ GetCA - Download CA certificate  
- ✅ Enroll - Certificate enrollment with AES/SHA256

#### Test Python SCEP Client
```powershell
.\tests\scripts\test_pyscep.ps1
```

Tests Python implementation of SCEP protocol:
- ✅ GetCaps - Query server capabilities
- ✅ GetCA - Download CA certificate
- ✅ Enroll - Certificate enrollment

### Test Output

All test artifacts are saved to the `tests/results/` directory:

**sscep outputs:**
- `test.key` - Generated private key (2048-bit RSA)
- `test.csr` - Certificate signing request
- `ca.crt` - Downloaded CA certificate (1,521 bytes)
- `enrolled.crt` - Enrolled certificate (1,996 bytes)

**Python outputs:**
- `py_test.key` - Generated private key (2048-bit RSA)
- `py_test.csr` - Certificate signing request
- `py_ca.crt` - Downloaded CA certificate (1,521 bytes)
- `py_enrolled.crt` - Enrolled certificate (2,000 bytes)
- `scep_response.bin` - Raw SCEP server response (debugging)

## SCEP Server Configuration

- **Endpoint**: http://localhost:8090/scep
- **CA Mode**: RSA (required for SCEP)
- **Supported Operations**: GetCACaps, GetCACert, PKIOperation (enrollment only)
- **Algorithms**:
  - Signature: SHA-256
  - Encryption: AES, 3DES
  - Hash: SHA-1, SHA-256, SHA-512

## Protocol Details

### Supported SCEP Operations

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

## Technical Notes

### Python Client Requirements
- Python 3.12+ with virtual environment at workspace `/.venv`
- Required packages: `cryptography`, `requests`, `asn1crypto`
- Imports modules from workspace root via `sys.path`

### Known Limitations
- Signature verification fails (expected - uses temporary self-signed cert)
- Python client is for debugging only; sscep is the production client
- Server only supports 3 core operations (GetCert, GetCRL, GetNextCA removed)

### Certificate Subject Preservation
Both clients properly preserve the CSR subject in the enrolled certificate:
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

## Troubleshooting

### Server Not Running
Ensure the Flask server is running on port 8090:
```powershell
.\scripts\restart_server.ps1
```

### Python Import Errors
All Python scripts in `tests/bin/` add the workspace root to `sys.path` automatically. If imports fail, verify the virtual environment is activated.

### Certificate Enrollment Fails
1. Check that `config.ini` has `mode = RSA` (not ECC)
2. Verify CA certificate exists: `pki-subca/rad_ca_sub_rsa.crt`
3. Check server logs: `logs/server.log`

### Test Files Cleanup
To clean up test artifacts:
```powershell
Remove-Item tests/results/* -ErrorAction SilentlyContinue
```
