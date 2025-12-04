# Basic API Test Script
# Tests core PKI server API endpoints (CA chain, CRL, certificate status, etc.)

Write-Host "=== Basic API Test Suite ===" -ForegroundColor Cyan

# Configuration
$SERVER = "https://localhost:443"
$TEST_DIR = ".\tests\results"
$ADMIN_USER = "admin"
$ADMIN_PASS = "pikachu"

# Create test directory if it doesn't exist
if (-not (Test-Path $TEST_DIR)) {
    New-Item -ItemType Directory -Path $TEST_DIR -Force | Out-Null
}

# Test counter
$testsPassed = 0
$testsFailed = 0

Write-Host ""

# ============================================================
# Test 1: Download CA Chain
# ============================================================

Write-Host "[Test 1/5] Download CA Chain" -ForegroundColor Yellow
Write-Host "    Endpoint: $SERVER/downloads/chain" -ForegroundColor Gray

$CA_CHAIN = "$TEST_DIR\ca_chain_test.crt"

try {
    curl.exe -k -s "$SERVER/downloads/chain" --output $CA_CHAIN 2>$null
    
    if (Test-Path $CA_CHAIN) {
        $chainSize = (Get-Item $CA_CHAIN).Length
        
        if ($chainSize -gt 0) {
            # Verify it's valid PEM format
            $content = Get-Content $CA_CHAIN -Raw
            if ($content -match "-----BEGIN CERTIFICATE-----") {
                Write-Host "[+] PASS: CA chain downloaded ($chainSize bytes)" -ForegroundColor Green
                
                # Count certificates in chain
                $certCount = ([regex]::Matches($content, "-----BEGIN CERTIFICATE-----")).Count
                Write-Host "    Contains $certCount certificate(s)" -ForegroundColor Gray
                $testsPassed++
            } else {
                Write-Host "[-] FAIL: Invalid PEM format" -ForegroundColor Red
                $testsFailed++
            }
        } else {
            Write-Host "[-] FAIL: Downloaded file is empty" -ForegroundColor Red
            $testsFailed++
        }
    } else {
        Write-Host "[-] FAIL: File not created" -ForegroundColor Red
        $testsFailed++
    }
} catch {
    Write-Host "[-] FAIL: $_" -ForegroundColor Red
    $testsFailed++
}

Write-Host ""

# ============================================================
# Test 2: Download CRL
# ============================================================

Write-Host "[Test 2/5] Download CRL (Certificate Revocation List)" -ForegroundColor Yellow
Write-Host "    Endpoint: $SERVER/downloads/crl" -ForegroundColor Gray

$CRL_FILE = "$TEST_DIR\crl_test.pem"

try {
    curl.exe -k -s "$SERVER/downloads/crl" --output $CRL_FILE 2>$null
    
    if (Test-Path $CRL_FILE) {
        $crlSize = (Get-Item $CRL_FILE).Length
        
        if ($crlSize -gt 0) {
            # Verify it's valid PEM format
            $content = Get-Content $CRL_FILE -Raw
            if ($content -match "-----BEGIN X509 CRL-----") {
                Write-Host "[+] PASS: CRL downloaded ($crlSize bytes)" -ForegroundColor Green
                
                # Try to inspect with OpenSSL
                $inspection = & openssl crl -in $CRL_FILE -text -noout 2>&1 | Select-Object -First 5
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "    CRL is valid and readable" -ForegroundColor Gray
                }
                $testsPassed++
            } else {
                Write-Host "[-] FAIL: Invalid CRL format" -ForegroundColor Red
                $testsFailed++
            }
        } else {
            Write-Host "[-] FAIL: Downloaded file is empty" -ForegroundColor Red
            $testsFailed++
        }
    } else {
        Write-Host "[-] FAIL: File not created" -ForegroundColor Red
        $testsFailed++
    }
} catch {
    Write-Host "[-] FAIL: $_" -ForegroundColor Red
    $testsFailed++
}

Write-Host ""

# ============================================================
# Test 3: Certificate Status Check
# ============================================================

Write-Host "[Test 3/5] Certificate Status Check" -ForegroundColor Yellow

# Find a valid certificate from previous tests
$validCert = $null
$certSerial = $null

$possibleCerts = @(
    "$TEST_DIR\enrolled.crt",
    "$TEST_DIR\py_enrolled.crt",
    ".\tests\estclient\etx.crt"
)

foreach ($cert in $possibleCerts) {
    if (Test-Path $cert) {
        $validCert = $cert
        # Extract serial number
        $serialOutput = & openssl x509 -in $cert -noout -serial 2>&1
        if ($LASTEXITCODE -eq 0 -and $serialOutput -match "serial=(.+)") {
            $certSerial = $matches[1]
            Write-Host "    Using certificate: $cert" -ForegroundColor Gray
            Write-Host "    Serial: $certSerial" -ForegroundColor Gray
            break
        }
    }
}

if ($certSerial) {
    try {
        $statusUrl = "$SERVER/status/$certSerial"
        Write-Host "    Endpoint: $statusUrl" -ForegroundColor Gray
        
        $response = curl.exe -k -s $statusUrl 2>$null
        
        if ($response) {
            $statusJson = $response | ConvertFrom-Json
            
            if ($statusJson.status) {
                $status = $statusJson.status
                Write-Host "[+] PASS: Certificate status retrieved: $status" -ForegroundColor Green
                
                if ($status -eq "valid" -or $status -eq "revoked") {
                    Write-Host "    Status is recognized ($status)" -ForegroundColor Gray
                }
                $testsPassed++
            } else {
                Write-Host "[-] FAIL: Invalid JSON response" -ForegroundColor Red
                $testsFailed++
            }
        } else {
            Write-Host "[-] FAIL: No response from server" -ForegroundColor Red
            $testsFailed++
        }
    } catch {
        Write-Host "[-] FAIL: $_" -ForegroundColor Red
        $testsFailed++
    }
} else {
    Write-Host "[!] SKIP: No valid certificate found from previous tests" -ForegroundColor Yellow
    Write-Host "    Run enrollment tests first (test_sscep.ps1 or test_estclient_curl.ps1)" -ForegroundColor Gray
}

Write-Host ""

# ============================================================
# Test 4: Expired Certificates List
# ============================================================

Write-Host "[Test 4/5] Expired Certificates List" -ForegroundColor Yellow
Write-Host "    Endpoint: $SERVER/expired" -ForegroundColor Gray

try {
    $response = curl.exe -k -s "$SERVER/expired" 2>$null
    
    if ($response) {
        # Check if response is an error message
        if ($response -like "*failed*" -or $response -like "*error*") {
            Write-Host "[-] FAIL: Server error - $response" -ForegroundColor Red
            $testsFailed++
        } else {
            try {
                $expiredList = $response | ConvertFrom-Json
                
                if ($expiredList.expired_cert_ids -is [Array] -or $expiredList.expired_cert_ids -eq $null) {
                    $count = if ($expiredList.expired_cert_ids) { $expiredList.expired_cert_ids.Count } else { 0 }
                    Write-Host "[+] PASS: Expired certificates list retrieved" -ForegroundColor Green
                    Write-Host "    Found $count expired certificate(s)" -ForegroundColor Gray
                    $testsPassed++
                } else {
                    Write-Host "[-] FAIL: Invalid response format" -ForegroundColor Red
                    $testsFailed++
                }
            } catch {
                Write-Host "[-] FAIL: Invalid JSON - $response" -ForegroundColor Red
                $testsFailed++
            }
        }
    } else {
        Write-Host "[-] FAIL: No response from server" -ForegroundColor Red
        $testsFailed++
    }
} catch {
    Write-Host "[-] FAIL: $_" -ForegroundColor Red
    $testsFailed++
}

Write-Host ""

# ============================================================
# Test 5: Download CSR (if exists)
# ============================================================

Write-Host "[Test 5/5] Download CSR" -ForegroundColor Yellow
Write-Host "    Endpoint: $SERVER/requests/1/download" -ForegroundColor Gray

$CSR_FILE = "$TEST_DIR\test_csr_download.pem"

try {
    # Try to download CSR with ID 1 using admin credentials
    $response = curl.exe -k -s -u "${ADMIN_USER}:${ADMIN_PASS}" "$SERVER/requests/1/download" 2>$null
    
    # Check if response is a redirect HTML
    if ($response -like "*Redirecting*" -or $response -like "*login*") {
        Write-Host "[!] SKIP: CSR download requires session-based authentication" -ForegroundColor Yellow
        Write-Host "    This endpoint requires web login (not HTTP Basic Auth)" -ForegroundColor Gray
        # Not counting as pass or fail - endpoint requires complex session auth
    } elseif ($response -like "*-----BEGIN CERTIFICATE REQUEST-----*") {
        # Save the CSR
        $response | Out-File -FilePath $CSR_FILE -Encoding ASCII
        $csrSize = (Get-Item $CSR_FILE).Length
        
        Write-Host "[+] PASS: CSR downloaded ($csrSize bytes)" -ForegroundColor Green
        
        # Try to inspect with OpenSSL
        $inspection = & openssl req -in $CSR_FILE -text -noout 2>&1 | Select-Object -First 3
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    CSR is valid and readable" -ForegroundColor Gray
        }
        $testsPassed++
    } elseif ($response -like "*404*" -or $response -like "*Not Found*") {
        Write-Host "[!] SKIP: CSR with ID 1 not found (404)" -ForegroundColor Yellow
        Write-Host "    This is expected if no CSR requests exist" -ForegroundColor Gray
    } else {
        Write-Host "[-] FAIL: Unexpected response" -ForegroundColor Red
        $testsFailed++
    }
} catch {
    Write-Host "[-] FAIL: $_" -ForegroundColor Red
    $testsFailed++
}

Write-Host ""

# ============================================================
# Test Summary
# ============================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Tests Passed: $testsPassed" -ForegroundColor Green
Write-Host "Tests Failed: $testsFailed" -ForegroundColor $(if ($testsFailed -eq 0) { "Green" } else { "Red" })
Write-Host ""

Write-Host "Generated files in $TEST_DIR directory:" -ForegroundColor Cyan
Write-Host ""

if (Test-Path "$TEST_DIR\ca_chain_test.crt") {
    $item = Get-Item "$TEST_DIR\ca_chain_test.crt"
    Write-Host "  ca_chain_test.crt  $($item.Length) bytes  $($item.LastWriteTime)" -ForegroundColor Gray
}

if (Test-Path "$TEST_DIR\crl_test.pem") {
    $item = Get-Item "$TEST_DIR\crl_test.pem"
    Write-Host "  crl_test.pem       $($item.Length) bytes  $($item.LastWriteTime)" -ForegroundColor Gray
}

if (Test-Path "$TEST_DIR\test_csr_download.pem") {
    $item = Get-Item "$TEST_DIR\test_csr_download.pem"
    Write-Host "  test_csr_download.pem  $($item.Length) bytes  $($item.LastWriteTime)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan

# Exit with appropriate code
if ($testsFailed -eq 0) {
    Write-Host "[+] All tests completed successfully!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[!] Some tests failed. Check output above." -ForegroundColor Yellow
    exit 1
}
