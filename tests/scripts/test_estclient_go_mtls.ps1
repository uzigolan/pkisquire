
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


# Set config path and workspace dir at the top
$WORKSPACE_DIR = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$CONFIG_PATH = Join-Path $WORKSPACE_DIR "config.ini"

$CA_MODE = Get-ConfigValue $CONFIG_PATH "CA" "mode"
if ($CA_MODE -eq "RSA") {
    $CA_CHAIN_PATH = Get-ConfigValue $CONFIG_PATH "CA" "CHAIN_FILE_PATH_RSA"
} else {
    $CA_CHAIN_PATH = Get-ConfigValue $CONFIG_PATH "CA" "CHAIN_FILE_PATH_EC"
}
$CA_CHAIN_WSL = Convert-ToWSLPath (Resolve-Path $CA_CHAIN_PATH).Path

Write-Host "CA chain path from config: $CA_CHAIN_PATH" -ForegroundColor Yellow
if ([string]::IsNullOrWhiteSpace($CA_CHAIN_PATH) -or -not (Test-Path $CA_CHAIN_PATH)) {
    Write-Host "[ERROR] CA chain file not found or not set: $CA_CHAIN_PATH" -ForegroundColor Red
    exit 1
}

# EST Client mTLS Test Script - Using estclient-go executable
# Tests EST enrollment with mTLS against the PKI server

Write-Host "=== EST Client mTLS Test (estclient-go) ===" -ForegroundColor Cyan

$WORKSPACE_DIR = (Get-Location).Path
$CONFIG_PATH = Join-Path $WORKSPACE_DIR "config.ini"
$TRUSTED_PORT = Get-ConfigValue $CONFIG_PATH "TRUSTED_HTTPS" "trusted_port"
$TRUSTED_CERT = Get-ConfigValue $CONFIG_PATH "TRUSTED_HTTPS" "trusted_ssl_cert"
$TRUSTED_KEY = Get-ConfigValue $CONFIG_PATH "TRUSTED_HTTPS" "trusted_ssl_key"
$CA_MODE = Get-ConfigValue $CONFIG_PATH "CA" "mode"
if ($CA_MODE -eq "RSA") {
    $CA_CHAIN_PATH = Get-ConfigValue $CONFIG_PATH "CA" "CHAIN_FILE_PATH_RSA"
} else {
    $CA_CHAIN_PATH = Get-ConfigValue $CONFIG_PATH "CA" "CHAIN_FILE_PATH_EC"
}
$WIN_IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*vEthernet*' -and $_.IPAddress -notlike '169.*' -and $_.IPAddress -notlike '127.*' } | Select-Object -First 1 -ExpandProperty IPAddress)
$SERVER = "https://localhost-wsl-win:${TRUSTED_PORT}"
$TEST_DIR = ".\tests\estclient"
$CSR_FILE = "$TEST_DIR\etx-estclient.csr"
$CERT_FILE = "$TEST_DIR\etx-estclient.crt"
$KEY_FILE = "$TEST_DIR\etx-estclient.key"

if (-not (Test-Path $TEST_DIR)) {
    New-Item -ItemType Directory -Path $TEST_DIR -Force | Out-Null
}

Write-Host "`n[*] Step 1: Generate EC Private Key (PKCS#8 PEM)" -ForegroundColor Yellow
& openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -nocrypt -out $KEY_FILE
if ($LASTEXITCODE -ne 0) { Write-Host "[-] Failed to generate private key (PKCS#8)" -ForegroundColor Red; exit 1 }
if (Test-Path $KEY_FILE) { Write-Host "[+] Private key (PKCS#8 PEM) saved to: $KEY_FILE" -ForegroundColor Green } else { Write-Host "[-] Private key file not created" -ForegroundColor Red; exit 1 }

$now = Get-Date
$cn = "estclient-go-mtls-$($now.Hour):$($now.Minute):$($now.Day):$($now.Month):$($now.Year)"

Write-Host "`n[*] Step 2: Generate Certificate Signing Request (CSR)" -ForegroundColor Yellow
& openssl req -new -key $KEY_FILE -out $CSR_FILE -subj "/CN=$cn"
if ($LASTEXITCODE -ne 0) { Write-Host "[-] Failed to generate CSR" -ForegroundColor Red; exit 1 }
if (Test-Path $CSR_FILE) { Write-Host "[+] CSR saved to: $CSR_FILE" -ForegroundColor Green } else { Write-Host "[-] CSR file not created" -ForegroundColor Red; exit 1 }

function Convert-ToWSLPath {
    param([string]$winPath)
    $drive, $rest = $winPath -split ':', 2
    $drive = $drive.ToLower()
    $rest = $rest.TrimStart('\')
    $wslPath = "/mnt/$drive/$rest"
    $wslPath = $wslPath -replace '\\', '/'
    return $wslPath
}

$CSR_FILE_WSL = Convert-ToWSLPath (Resolve-Path $CSR_FILE).Path
$KEY_FILE_WSL = Convert-ToWSLPath (Resolve-Path $KEY_FILE).Path
$CERT_FILE_WSL = Convert-ToWSLPath (Resolve-Path $CERT_FILE).Path
$TRUSTED_CERT_WSL = Convert-ToWSLPath (Resolve-Path $TRUSTED_CERT).Path
$TRUSTED_KEY_PKCS8 = "$TEST_DIR\pikachu_issued_https_pkcs8.key"
Write-Host "Converting client key to PKCS#8 format for mTLS..."
& openssl pkcs8 -topk8 -nocrypt -in $TRUSTED_KEY -out $TRUSTED_KEY_PKCS8
if ($LASTEXITCODE -ne 0) { Write-Host "[-] Failed to convert client key to PKCS#8" -ForegroundColor Red; exit 1 }
$TRUSTED_KEY_WSL = Convert-ToWSLPath (Resolve-Path $TRUSTED_KEY_PKCS8).Path
$CA_CHAIN_WSL = Convert-ToWSLPath (Resolve-Path $CA_CHAIN_PATH).Path

# Use -explicit for CA trust, -certs for client cert
 $enrollCmd = "wsl ~/go/bin/estclient enroll -server $SERVER -csr '$CSR_FILE_WSL' -key '$KEY_FILE_WSL' -out '$CERT_FILE_WSL' -explicit '$CA_CHAIN_WSL' -certs '$TRUSTED_CERT_WSL' -key '$TRUSTED_KEY_WSL'"
Write-Host "    Command: $enrollCmd" -ForegroundColor Gray

Invoke-Expression $enrollCmd

if ($LASTEXITCODE -ne 0) { Write-Host "[-] estclient-go mTLS enrollment failed with exit code $LASTEXITCODE" -ForegroundColor Red; exit 1 }
if (Test-Path $CERT_FILE) { Write-Host "[+] Certificate saved to: $CERT_FILE" -ForegroundColor Green } else { Write-Host "[-] Certificate file not created" -ForegroundColor Red; exit 1 }

Write-Host "`n[+] EST Client mTLS Test Complete!" -ForegroundColor Green
Write-Host "`nGenerated files:" -ForegroundColor Cyan
Write-Host "  Private Key: $KEY_FILE" -ForegroundColor Gray
Write-Host "  CSR:         $CSR_FILE" -ForegroundColor Gray
Write-Host "  Cert:        $CERT_FILE" -ForegroundColor Gray
