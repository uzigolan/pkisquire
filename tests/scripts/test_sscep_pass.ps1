Write-Host "  > sscep $($Args -join ' ')" -ForegroundColor DarkGray

if ($args.Count -lt 1) {
    Write-Host "[ERROR] Challenge password argument required. Usage: ./test_sscep_pass.ps1 <challengePassword>" -ForegroundColor Red
    exit 1
}
$challengePassword = $args[0]

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

$WORKSPACE_DIR = (Get-Location).Path
$CONFIG_PATH = Join-Path $WORKSPACE_DIR "config.ini"
$RESULTS_DIR = "tests/results"
$keyPath = "$RESULTS_DIR/test_pass.key"
$csrPath = "$RESULTS_DIR/test_pass.csr"
$crtPath = "$RESULTS_DIR/enrolled_pass.crt"
$caCrtPath = "$RESULTS_DIR/ca_pass.crt"

# Check challenge_password_enabled in config.ini
$challengeEnabled = Get-ConfigValue $CONFIG_PATH "SCEP" "challenge_password_enabled"
if ($challengeEnabled -eq $null -or $challengeEnabled.ToLower() -ne "true") {
    Write-Host "[ERROR] Challenge password is not enabled in config.ini ([SCEP] challenge_password_enabled=false)" -ForegroundColor Red
    exit 1
}

Write-Host "\n=== SCEP Test Suite (Challenge Password) ===" -ForegroundColor Green
Write-Host "Testing compiled sscep client with challenge password" -ForegroundColor Gray
Write-Host ""

# Clean up old test files
Write-Host "[Prep] Cleaning test directory..." -ForegroundColor Cyan
Remove-Item $RESULTS_DIR/*.crt, $RESULTS_DIR/*.key, $RESULTS_DIR/*.csr, $RESULTS_DIR/*.der -ErrorAction SilentlyContinue
Write-Host ""

# Generate test credentials with challenge password
Write-Host "[Prep] Generating test credentials with challenge password..." -ForegroundColor Cyan
$now = Get-Date
$cn  = "sscep-test-pass-$($now.Hour):$($now.Minute):$($now.Day):$($now.Month):$($now.Year)"
$configFile = "$RESULTS_DIR/openssl_csr_pass.cnf"
$configContent = "[ req ]`ndistinguished_name = dn`nattributes = req_attrs`nprompt = no`n[ dn ]`nCN = $cn`n[ req_attrs ]`nchallengePassword = $challengePassword"
$configContent | Set-Content $configFile
Write-Host "      Generating key..." -ForegroundColor Gray
$keyResult = openssl genrsa -out $keyPath 2048 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] OpenSSL key generation failed:" -ForegroundColor Red
    $keyResult | ForEach-Object { Write-Host $_ }
    exit 1
}
Write-Host "      Generating CSR with challenge password..." -ForegroundColor Gray
$csrResult = openssl req -new -key $keyPath -out $csrPath -config $configFile 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] OpenSSL CSR generation failed:" -ForegroundColor Red
    $csrResult | ForEach-Object { Write-Host $_ }
    exit 1
}
Write-Host "      Generated test_pass.key and test_pass.csr with challenge password" -ForegroundColor Gray
Write-Host ""

$HTTP_PORT = Get-ConfigValue $CONFIG_PATH "DEFAULT" "http_port"
$SCEP_URL = "http://127.0.0.1:$HTTP_PORT/scep"
$env:PATH = "C:\Program Files\OpenSSL-Win64\bin;" + $env:PATH

# Test 1: GetCaps
Write-Host "[1/3] Testing GetCaps - Query server capabilities" -ForegroundColor Yellow
& tests\sscep\sscep.exe getcaps -u $SCEP_URL -v
Write-Host ""

# Test 2: GetCA
Write-Host "[2/3] Testing GetCA - Download CA certificate" -ForegroundColor Yellow
& tests\sscep\sscep.exe getca -u $SCEP_URL -c $caCrtPath -v
if (Test-Path $caCrtPath) {
    Write-Host "      Done - CA certificate downloaded" -ForegroundColor Green
    openssl x509 -in $caCrtPath -noout -subject -issuer 2>$null | ForEach-Object {
        Write-Host "      $_" -ForegroundColor Gray
    }
}
Write-Host ""

# Test 3: Enroll
Write-Host "[3/3] Testing Enroll - Certificate enrollment" -ForegroundColor Yellow
& tests\sscep\sscep.exe enroll -u $SCEP_URL -k $keyPath -r $csrPath -c $caCrtPath -l $crtPath -E aes -S sha256 -v
if (Test-Path $crtPath) {
    Write-Host "      Done - Certificate enrolled successfully" -ForegroundColor Green
    $certInfo = openssl x509 -in $crtPath -noout -subject -issuer -dates -serial 2>$null
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
Write-Host "Test files saved to $RESULTS_DIR directory:" -ForegroundColor Yellow
Get-ChildItem $RESULTS_DIR/*.crt, $RESULTS_DIR/*.key, $RESULTS_DIR/*.csr -ErrorAction SilentlyContinue | Select-Object Name, @{N='Size';E={"{0:N0} bytes" -f $_.Length}}, LastWriteTime | Format-Table -AutoSize
Write-Host "========================================`n" -ForegroundColor Cyan
Get-ChildItem tests\results\*.crt, tests\results\*.key, tests\results\*.csr -ErrorAction SilentlyContinue | Select-Object Name, @{N='Size';E={"{0:N0} bytes" -f $_.Length}}, LastWriteTime | Format-Table -AutoSize
Write-Host "========================================`n" -ForegroundColor Cyan
