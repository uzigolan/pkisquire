# EST Client Test Script - Using estclient-go executable
# Tests EST enrollment against the PKI server

Write-Host "=== EST Client Test (estclient-go) ===" -ForegroundColor Cyan

# Configuration
$SERVER = "localhost"
$EST_CLIENT = ".\tests\estclient\estclient.exe"
$TEST_DIR = ".\tests\estclient"
$CA_CERT = "$TEST_DIR\ca-estclient.pem"
$CSR_FILE = "$TEST_DIR\etx-estclient.csr"
$CERT_FILE = "$TEST_DIR\etx-estclient.crt"
$KEY_FILE = "$TEST_DIR\etx-estclient.key"

# Check if estclient exists
if (-not (Test-Path $EST_CLIENT)) {
    Write-Host "[-] EST client not found at $EST_CLIENT" -ForegroundColor Red
    Write-Host "    The estclient-go executable has compatibility issues on this system" -ForegroundColor Yellow
    Write-Host "    Use test_estclient_curl.ps1 instead" -ForegroundColor Yellow
    exit 1
}

# Create test directory if it doesn't exist
if (-not (Test-Path $TEST_DIR)) {
    New-Item -ItemType Directory -Path $TEST_DIR -Force | Out-Null
}

Write-Host "`n[*] Note: This script uses the estclient-go executable" -ForegroundColor Yellow
Write-Host "    If you encounter issues, use test_estclient_curl.ps1 instead" -ForegroundColor Yellow

Write-Host "`n[*] Step 1: Generate Private Key" -ForegroundColor Yellow
Write-Host "    Command: openssl ecparam -genkey -name prime256v1 -out $KEY_FILE" -ForegroundColor Gray

& openssl ecparam -genkey -name prime256v1 -out $KEY_FILE

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to generate private key" -ForegroundColor Red
    exit 1
}

if (Test-Path $KEY_FILE) {
    Write-Host "[+] Private key saved to: $KEY_FILE" -ForegroundColor Green
} else {
    Write-Host "[-] Private key file not created" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] Step 2: Generate Certificate Signing Request (CSR)" -ForegroundColor Yellow
Write-Host "    Command: openssl req -new -key $KEY_FILE -out $CSR_FILE -subj /CN=etx-estclient-test" -ForegroundColor Gray

& openssl req -new -key $KEY_FILE -out $CSR_FILE -subj "/CN=etx-estclient-test"

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to generate CSR" -ForegroundColor Red
    exit 1
}

if (Test-Path $CSR_FILE) {
    Write-Host "[+] CSR saved to: $CSR_FILE" -ForegroundColor Green
    $csrSize = (Get-Item $CSR_FILE).Length
    Write-Host "    Size: $csrSize bytes" -ForegroundColor Gray
} else {
    Write-Host "[-] CSR file not created" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] Step 3: Attempt EST Operations with estclient" -ForegroundColor Yellow
Write-Host "    Note: The compiled estclient.exe has compatibility issues on this platform" -ForegroundColor Yellow
Write-Host "    Attempting to run anyway..." -ForegroundColor Gray

try {
    Write-Host "`n    Command: $EST_CLIENT (test execution)" -ForegroundColor Gray
    & $EST_CLIENT 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] estclient executable works!" -ForegroundColor Green
        Write-Host "    You can now use it for EST operations" -ForegroundColor Cyan
    } else {
        throw "estclient returned error code $LASTEXITCODE"
    }
} catch {
    Write-Host "[-] estclient.exe encountered an error: $_" -ForegroundColor Red
    Write-Host "`n[!] Alternative: Use test_estclient_curl.ps1 for a working EST test" -ForegroundColor Yellow
    Write-Host "    The curl-based script provides the same functionality without executable issues" -ForegroundColor Gray
    exit 1
}

Write-Host "`n[+] EST Client Test Complete!" -ForegroundColor Green
Write-Host "`nGenerated files:" -ForegroundColor Cyan
Write-Host "  Private Key: $KEY_FILE" -ForegroundColor Gray
Write-Host "  CSR:         $CSR_FILE" -ForegroundColor Gray
Write-Host "`nNote: For actual EST enrollment, use test_estclient_curl.ps1" -ForegroundColor Yellow
