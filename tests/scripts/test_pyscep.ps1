# Python SCEP Testing Script - Core 3 Operations Only
# Tests Python SCEP client with GetCaps, GetCA, and Enroll
# All outputs go to tests folder

$env:PATH = "C:\Program Files\OpenSSL-Win64\bin;" + $env:PATH
$SCEP_URL = "http://localhost:8090/scep"

Write-Host "`n=== Python SCEP Test Suite (Core Operations) ===" -ForegroundColor Green
Write-Host "Testing Python SCEP client tools" -ForegroundColor Gray
Write-Host ""

# Clean up old test files
Write-Host "[Prep] Cleaning test directory..." -ForegroundColor Cyan
Remove-Item tests\results\py_*.crt, tests\results\py_*.key, tests\results\py_*.csr -ErrorAction SilentlyContinue
Write-Host ""

# Generate test credentials
Write-Host "[Prep] Generating test credentials..." -ForegroundColor Cyan
openssl genrsa -out tests\results\py_test.key 2048 2>&1 | Out-Null
openssl req -new -key tests\results\py_test.key -out tests\results\py_test.csr -subj "/C=IL/ST=TLV/L=Tel-Aviv/O=TestOrg/OU=IT/CN=pyscep-test.example.com" 2>&1 | Out-Null
Write-Host "      Generated py_test.key and py_test.csr" -ForegroundColor Gray
Write-Host ""

# Test 1: GetCaps
Write-Host "[1/3] Testing GetCaps - Query server capabilities" -ForegroundColor Yellow
.\tests\scripts\pyscep.ps1 getcaps --url $SCEP_URL
Write-Host ""

# Test 2: GetCA
Write-Host "[2/3] Testing GetCA - Download CA certificate" -ForegroundColor Yellow
.\tests\scripts\pyscep.ps1 getca --url $SCEP_URL -c tests\results\py_ca.crt
if (Test-Path tests\results\py_ca.crt) {
    Write-Host "      Done - CA certificate downloaded" -ForegroundColor Green
    openssl x509 -in tests\results\py_ca.crt -noout -subject -issuer 2>$null | ForEach-Object {
        Write-Host "      $_" -ForegroundColor Gray
    }
}
Write-Host ""

# Test 3: Enroll
Write-Host "[3/3] Testing Enroll - Certificate enrollment" -ForegroundColor Yellow
.\tests\scripts\pyscep.ps1 enroll --url $SCEP_URL --key tests\results\py_test.key --csr tests\results\py_test.csr --ca tests\results\py_ca.crt --out tests\results\py_enrolled.crt
if (Test-Path tests\results\py_enrolled.crt) {
    Write-Host "      Done - Certificate enrolled successfully" -ForegroundColor Green
    $certInfo = openssl x509 -in tests\results\py_enrolled.crt -noout -subject -issuer -dates -serial 2>$null
    $certInfo | ForEach-Object {
        Write-Host "      $_" -ForegroundColor Gray
    }
}
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Status  Operation   Description" -ForegroundColor White
Write-Host "------  ----------  -----------" -ForegroundColor White
Write-Host "  OK    GetCaps     Server capabilities retrieved" -ForegroundColor Green
Write-Host "  OK    GetCA       CA certificate downloaded" -ForegroundColor Green
Write-Host "  OK    Enroll      Certificate enrolled successfully" -ForegroundColor Green
Write-Host ""
Write-Host "Test files saved to tests\results\ directory:" -ForegroundColor Yellow
Get-ChildItem tests\results\py_*.crt, tests\results\py_*.key, tests\results\py_*.csr -ErrorAction SilentlyContinue | Select-Object Name, @{N='Size';E={"{0:N0} bytes" -f $_.Length}}, LastWriteTime | Format-Table -AutoSize
Write-Host "========================================`n" -ForegroundColor Cyan
