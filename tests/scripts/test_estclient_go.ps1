# ...existing code...
# EST Client Test Script - Using estclient-go executable
# Tests EST enrollment against the PKI server

Write-Host "=== EST Client Test (estclient-go) ===" -ForegroundColor Cyan


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
    $HTTPS_PORT = Get-ConfigValue $CONFIG_PATH "HTTPS" "port"
    # Detect Windows host IP for WSL access
    $WIN_IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*vEthernet*' -and $_.IPAddress -notlike '169.*' -and $_.IPAddress -notlike '127.*' } | Select-Object -First 1 -ExpandProperty IPAddress)
    $SERVER = "${WIN_IP}:${HTTPS_PORT}"
$ESTCLIENT_WSL = "estclient"
$TEST_DIR = ".\tests\estclient"
$CA_CERT = "$TEST_DIR\ca-estclient.pem"
$CSR_FILE = "$TEST_DIR\etx-estclient.csr"
$CERT_FILE = "$TEST_DIR\etx-estclient.crt"
$KEY_FILE = "$TEST_DIR\etx-estclient.key"

# No need to check for Windows estclient.exe; using WSL estclient

# Create test directory if it doesn't exist
if (-not (Test-Path $TEST_DIR)) {
    New-Item -ItemType Directory -Path $TEST_DIR -Force | Out-Null
}

Write-Host "`n[*] Note: This script uses the estclient-go executable" -ForegroundColor Yellow
Write-Host "    If you encounter issues, use test_estclient_curl.ps1 instead" -ForegroundColor Yellow


Write-Host "`n[*] Step 1: Generate EC Private Key (PKCS#8 PEM)" -ForegroundColor Yellow
Write-Host "    Command: openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -nocrypt -out $KEY_FILE" -ForegroundColor Gray

# Generate EC key and convert to PKCS#8 PEM
& openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -nocrypt -out $KEY_FILE

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to generate private key (PKCS#8)" -ForegroundColor Red
    exit 1
}

if (Test-Path $KEY_FILE) {
    Write-Host "[+] Private key (PKCS#8 PEM) saved to: $KEY_FILE" -ForegroundColor Green
} else {
    Write-Host "[-] Private key file not created" -ForegroundColor Red
    exit 1
}



# Generate dynamic CN: estclient-go-hr:min:day:month:year
$now = Get-Date
$cn = "estclient-go-$($now.Hour):$($now.Minute):$($now.Day):$($now.Month):$($now.Year)"


Write-Host "`n[*] Step 2: Generate Certificate Signing Request (CSR)" -ForegroundColor Yellow
Write-Host "    Command: openssl req -new -key $KEY_FILE -out $CSR_FILE -subj /CN=$cn" -ForegroundColor Gray

& openssl req -new -key $KEY_FILE -out $CSR_FILE -subj "/CN=$cn"

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


Write-Host "`n[*] Step 3: Perform EST Enrollment with estclient (WSL) using a given CSR" -ForegroundColor Yellow


# Convert Windows paths to WSL paths dynamically
function Convert-ToWSLPath {
    param([string]$winPath)
    $full = [IO.Path]::GetFullPath($winPath)
    $full = $full -replace '\\', '/'
    $drive = $full.Substring(0,1).ToLower()
    $rest = $full.Substring(2)
    return "/mnt/$drive/$rest"
}

$CSR_FILE_WSL = Convert-ToWSLPath $CSR_FILE
$KEY_FILE_WSL = Convert-ToWSLPath $KEY_FILE
$CERT_FILE_WSL = Convert-ToWSLPath $CERT_FILE

 $enrollCmd = "wsl ~/go/bin/estclient enroll -server $SERVER -csr '$CSR_FILE_WSL' -key '$KEY_FILE_WSL' -out '$CERT_FILE_WSL' -insecure"
Write-Host "    Command: $enrollCmd" -ForegroundColor Gray

# Run the estclient enrollment in WSL
Invoke-Expression $enrollCmd

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] estclient-go enrollment failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}

if (Test-Path $CERT_FILE) {
    Write-Host "[+] Certificate saved to: $CERT_FILE" -ForegroundColor Green
    $certSize = (Get-Item $CERT_FILE).Length
    Write-Host "    Size: $certSize bytes" -ForegroundColor Gray
} else {
    Write-Host "[-] Certificate file not created" -ForegroundColor Red
    exit 1
}

Write-Host "`n[+] EST Client Test Complete!" -ForegroundColor Green
Write-Host "`nGenerated files:" -ForegroundColor Cyan
Write-Host "  Private Key: $KEY_FILE" -ForegroundColor Gray
Write-Host "  CSR:         $CSR_FILE" -ForegroundColor Gray
Write-Host "`nNote: For actual EST enrollment, use test_estclient_curl.ps1" -ForegroundColor Yellow
