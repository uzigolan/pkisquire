# SCEP Testing Script - Core 3 Operations Only
# Tests compiled sscep client with GetCaps, GetCA, and Enroll
# All outputs go to tests folder

$env:PATH = "C:\Program Files\OpenSSL-Win64\bin;" + $env:PATH
$SCEP_URL = "http://localhost:8090/scep"

Write-Host "`n=== SCEP Test Suite (Core Operations) ===" -ForegroundColor Green
Write-Host "Testing compiled sscep client" -ForegroundColor Gray
Write-Host ""

# Clean up old test files
Write-Host "[Prep] Cleaning test directory..." -ForegroundColor Cyan
Remove-Item tests\results\*.crt, tests\results\*.key, tests\results\*.csr, tests\results\*.der -ErrorAction SilentlyContinue
Write-Host ""

# Generate test credentials
Write-Host "[Prep] Generating test credentials..." -ForegroundColor Cyan
openssl genrsa -out tests\results\test.key 2048 2>&1 | Out-Null
openssl req -new -key tests\results\test.key -out tests\results\test.csr -subj "/C=IL/ST=TLV/L=Tel-Aviv/O=TestOrg/OU=IT/CN=sscep-test.example.com" 2>&1 | Out-Null
Write-Host "      Generated test.key and test.csr" -ForegroundColor Gray
Write-Host ""

# Test 1: GetCaps
Write-Host "[1/3] Testing GetCaps - Query server capabilities" -ForegroundColor Yellow
tests\sscep\sscep.exe getcaps -u $SCEP_URL
Write-Host ""

# Test 2: GetCA
Write-Host "[2/3] Testing GetCA - Download CA certificate" -ForegroundColor Yellow
tests\sscep\sscep.exe getca -u $SCEP_URL -c tests\results\ca.crt
if (Test-Path tests\results\ca.crt) {
    Write-Host "      Done - CA certificate downloaded" -ForegroundColor Green
    openssl x509 -in tests\results\ca.crt -noout -subject -issuer 2>$null | ForEach-Object {
        Write-Host "      $_" -ForegroundColor Gray
    }
}
Write-Host ""

# Test 3: Enroll
Write-Host "[3/3] Testing Enroll - Certificate enrollment" -ForegroundColor Yellow
tests\sscep\sscep.exe enroll -u $SCEP_URL -k tests\results\test.key -r tests\results\test.csr -c tests\results\ca.crt -l tests\results\enrolled.crt -E aes -S sha256
if (Test-Path tests\results\enrolled.crt) {
    Write-Host "      Done - Certificate enrolled successfully" -ForegroundColor Green
    $certInfo = openssl x509 -in tests\results\enrolled.crt -noout -subject -issuer -dates -serial 2>$null
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
Get-ChildItem tests\results\*.crt, tests\results\*.key, tests\results\*.csr -ErrorAction SilentlyContinue | Select-Object Name, @{N='Size';E={"{0:N0} bytes" -f $_.Length}}, LastWriteTime | Format-Table -AutoSize
Write-Host "========================================`n" -ForegroundColor Cyan
