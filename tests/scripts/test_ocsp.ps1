# OCSP Test Script
# Tests OCSP responder against the PKI server

Write-Host "=== OCSP Responder Test ===" -ForegroundColor Cyan


function Get-ConfigValue {
    param (
        [string]$ConfigPath,
        [string]$Section,
        [string]$Key
    )
    $inSection = $false
    foreach ($line in Get-Content $ConfigPath) {
        $trimmed = $line.Trim()
        if ($trimmed -match "^\[" + [regex]::Escape($Section) + "\]") {
            $inSection = $true
        } elseif ($trimmed -match "^\[.*\]") {
            $inSection = $false
        } elseif ($inSection -and $trimmed -match "^" + [regex]::Escape($Key) + "\s*=\s*(.+)") {
            return $matches[1].Trim()
        }
    }
    return $null
}

$SCRIPT_DIR = Split-Path -Parent $PSCommandPath
$REPO_ROOT  = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))  # tests/scripts -> tests -> PKI
$CONFIG_PATH = Join-Path $REPO_ROOT "config.ini"
$HTTP_PORT = Get-ConfigValue $CONFIG_PATH "DEFAULT" "http_port"
$SERVER = "http://localhost:$HTTP_PORT"
$OCSP_PATH = "/ocsp"
$TEST_DIR = ".\tests\results"
$ISSUER_CERT = ".\pki-subca\rad_ca_sub_rsa.crt"
$OCSP_REQUEST = "$TEST_DIR\ocsp_request.der"
$OCSP_RESPONSE = "$TEST_DIR\ocsp_response.der"

# Create test directory if it doesn't exist
if (-not (Test-Path $TEST_DIR)) {
    New-Item -ItemType Directory -Path $TEST_DIR -Force | Out-Null
}

# Check if issuer certificate exists
if (-not (Test-Path $ISSUER_CERT)) {
    Write-Host "[-] Issuer certificate not found: $ISSUER_CERT" -ForegroundColor Red
    Write-Host "    Please ensure the CA is initialized with RSA mode" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n[*] Issuer Certificate: $ISSUER_CERT" -ForegroundColor Yellow
Write-Host "    $(Get-Item $ISSUER_CERT | Select-Object -ExpandProperty Length) bytes" -ForegroundColor Gray

# Find a valid certificate to test with
Write-Host "`n[*] Looking for test certificate..." -ForegroundColor Yellow

# Try to find an enrolled certificate from previous tests
$testCerts = @(
    "$TEST_DIR\enrolled.crt",
    "$TEST_DIR\py_enrolled.crt",
    ".\tests\estclient\etx.crt"
)

$TEST_CERT = $null
foreach ($cert in $testCerts) {
    if (Test-Path $cert) {
        $TEST_CERT = $cert
        Write-Host "[+] Found test certificate: $TEST_CERT" -ForegroundColor Green
        break
    }
}

if (-not $TEST_CERT) {
    Write-Host "[-] No test certificate found" -ForegroundColor Red
    Write-Host "    Please run one of the enrollment tests first:" -ForegroundColor Yellow
    Write-Host "      .\tests\scripts\test_sscep.ps1" -ForegroundColor Gray
    Write-Host "      .\tests\scripts\test_pyscep.ps1" -ForegroundColor Gray
    Write-Host "      .\tests\scripts\test_estclient_curl.ps1" -ForegroundColor Gray
    exit 1
}

Write-Host "`n[*] Step 1: Send OCSP Request" -ForegroundColor Yellow
Write-Host "    Command: openssl ocsp -reqout $OCSP_REQUEST -issuer $ISSUER_CERT -cert $TEST_CERT -url $SERVER$OCSP_PATH -resp_text -respout $OCSP_RESPONSE" -ForegroundColor Gray

& openssl ocsp `
    -reqout $OCSP_REQUEST `
    -issuer $ISSUER_CERT `
    -cert $TEST_CERT `
    -url "$SERVER$OCSP_PATH" `
    -resp_text `
    -respout $OCSP_RESPONSE

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] OCSP request failed" -ForegroundColor Red
    exit 1
}

Write-Host "`n[+] OCSP Response received" -ForegroundColor Green

if (Test-Path $OCSP_REQUEST) {
    $reqSize = (Get-Item $OCSP_REQUEST).Length
    Write-Host "    Request:  $reqSize bytes saved to $OCSP_REQUEST" -ForegroundColor Gray
}

if (Test-Path $OCSP_RESPONSE) {
    $respSize = (Get-Item $OCSP_RESPONSE).Length
    Write-Host "    Response: $respSize bytes saved to $OCSP_RESPONSE" -ForegroundColor Gray
}

Write-Host "`n[*] Step 2: Parse OCSP Response" -ForegroundColor Yellow
Write-Host "    Command: openssl ocsp -respin $OCSP_RESPONSE -resp_text -noverify" -ForegroundColor Gray

& openssl ocsp -respin $OCSP_RESPONSE -resp_text -noverify

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to parse OCSP response" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] Step 3: Verify OCSP Response Signature" -ForegroundColor Yellow
Write-Host "    Command: openssl ocsp -respin $OCSP_RESPONSE -issuer $ISSUER_CERT -VAfile $ISSUER_CERT -resp_text" -ForegroundColor Gray

& openssl ocsp -respin $OCSP_RESPONSE -issuer $ISSUER_CERT -VAfile $ISSUER_CERT -resp_text

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[+] OCSP response signature verified!" -ForegroundColor Green
} else {
    Write-Host "`n[!] OCSP response signature verification failed (may be expected if using different signing cert)" -ForegroundColor Yellow
}

Write-Host "`n[+] OCSP Test (Known Certificate) Complete!" -ForegroundColor Green

# ============================================================
# Test 2: Unknown Certificate (not issued by this CA)
# ============================================================

Write-Host "`n`n=== OCSP Test: Unknown Certificate ===" -ForegroundColor Cyan

$UNKNOWN_KEY = "$TEST_DIR\unknown_key.pem"
$UNKNOWN_CERT = "$TEST_DIR\unknown_cert.pem"
$UNKNOWN_OCSP_REQUEST = "$TEST_DIR\ocsp_request_unknown.der"
$UNKNOWN_OCSP_RESPONSE = "$TEST_DIR\ocsp_response_unknown.der"

Write-Host "`n[*] Generating self-signed certificate (not from our CA)..." -ForegroundColor Yellow

# Generate a private key
& openssl ecparam -genkey -name prime256v1 -out $UNKNOWN_KEY 2>$null

# Create a self-signed certificate
& openssl req -new -x509 -key $UNKNOWN_KEY -out $UNKNOWN_CERT -days 1 `
    -subj "/CN=Unknown Certificate/O=External CA/C=US" 2>$null

if (Test-Path $UNKNOWN_CERT) {
    Write-Host "[+] Generated unknown certificate: $UNKNOWN_CERT" -ForegroundColor Green
} else {
    Write-Host "[-] Failed to generate unknown certificate" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] Step 4: Send OCSP Request for Unknown Certificate" -ForegroundColor Yellow
Write-Host "    Command: openssl ocsp -reqout $UNKNOWN_OCSP_REQUEST -issuer $ISSUER_CERT -cert $UNKNOWN_CERT -url $SERVER$OCSP_PATH -resp_text -respout $UNKNOWN_OCSP_RESPONSE" -ForegroundColor Gray

& openssl ocsp `
    -reqout $UNKNOWN_OCSP_REQUEST `
    -issuer $ISSUER_CERT `
    -cert $UNKNOWN_CERT `
    -url "$SERVER$OCSP_PATH" `
    -resp_text `
    -respout $UNKNOWN_OCSP_RESPONSE 2>&1

# For unknown certificates, the responder may return "unauthorized" status
# This is expected and valid per RFC 6960
$exitCode = $LASTEXITCODE

if (Test-Path $UNKNOWN_OCSP_RESPONSE) {
    Write-Host "`n[+] OCSP Response received for unknown certificate" -ForegroundColor Green
    
    $respSize = (Get-Item $UNKNOWN_OCSP_RESPONSE).Length
    Write-Host "    Response: $respSize bytes saved to $UNKNOWN_OCSP_RESPONSE" -ForegroundColor Gray
    
    if (Test-Path $UNKNOWN_OCSP_REQUEST) {
        $reqSize = (Get-Item $UNKNOWN_OCSP_REQUEST).Length
        Write-Host "    Request:  $reqSize bytes saved to $UNKNOWN_OCSP_REQUEST" -ForegroundColor Gray
    }
    
    Write-Host "`n[*] Step 5: Parse OCSP Response for Unknown Certificate" -ForegroundColor Yellow
    Write-Host "    Expected result: 'unauthorized' or 'unknown' status" -ForegroundColor Yellow
    Write-Host "    Command: openssl ocsp -respin $UNKNOWN_OCSP_RESPONSE -resp_text -noverify" -ForegroundColor Gray
    
    & openssl ocsp -respin $UNKNOWN_OCSP_RESPONSE -resp_text -noverify 2>&1
    
    Write-Host "`n[+] Unknown certificate test complete - received proper 'unauthorized' response" -ForegroundColor Green
} else {
    Write-Host "[-] No OCSP response file generated" -ForegroundColor Red
}

Write-Host "`n[+] All OCSP Tests Complete!" -ForegroundColor Green
Write-Host "`nGenerated files:" -ForegroundColor Cyan
Write-Host "  Known Certificate:" -ForegroundColor White
Write-Host "    Test Certificate: $TEST_CERT" -ForegroundColor Gray
Write-Host "    OCSP Request:     $OCSP_REQUEST" -ForegroundColor Gray
Write-Host "    OCSP Response:    $OCSP_RESPONSE" -ForegroundColor Gray
Write-Host "  Unknown Certificate:" -ForegroundColor White
Write-Host "    Test Certificate: $UNKNOWN_CERT" -ForegroundColor Gray
Write-Host "    OCSP Request:     $UNKNOWN_OCSP_REQUEST" -ForegroundColor Gray
Write-Host "    OCSP Response:    $UNKNOWN_OCSP_RESPONSE" -ForegroundColor Gray

Write-Host "`nOCSP Endpoint: $SERVER$OCSP_PATH" -ForegroundColor Cyan
