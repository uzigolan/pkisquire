<#
EST Client mTLS Test Script - Using curl with client certs
Tests EST enrollment with mTLS against the PKI server
CA chain file selection is based on [CA].mode in config.ini
If mode=RSA, uses pki-subca/rad_chain_rsa.crt
If mode=EC, uses pki-subca/rad_chain_ec.crt
#>

Write-Host "=== EST Client mTLS Test (curl, mTLS) ===" -ForegroundColor Cyan

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

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$CONFIG_PATH = Join-Path $repoRoot "config.ini"

$TRUSTED_PORT = Get-ConfigValue $CONFIG_PATH "TRUSTED_HTTPS" "trusted_port"
$TRUSTED_CERT = Get-ConfigValue $CONFIG_PATH "TRUSTED_HTTPS" "trusted_ssl_cert"
$TRUSTED_KEY = Get-ConfigValue $CONFIG_PATH "TRUSTED_HTTPS" "trusted_ssl_key"
$CA_MODE = Get-ConfigValue $CONFIG_PATH "CA" "mode"
$CA_CHAIN_PATH = $null
if ($CA_MODE -eq "RSA") {
    $CA_CHAIN_PATH = Get-ConfigValue $CONFIG_PATH "CA" "CHAIN_FILE_PATH_RSA"
    Write-Host "[Config] CA mode: RSA. Using chain file: $CA_CHAIN_PATH" -ForegroundColor Cyan
} elseif ($CA_MODE -eq "EC") {
    $CA_CHAIN_PATH = Get-ConfigValue $CONFIG_PATH "CA" "CHAIN_FILE_PATH_EC"
    Write-Host "[Config] CA mode: EC. Using chain file: $CA_CHAIN_PATH" -ForegroundColor Cyan
} else {
    Write-Host "[Config] Unknown CA mode: $CA_MODE. Exiting." -ForegroundColor Red
    exit 1
}
$SERVER = "https://localhost:$TRUSTED_PORT"
$EST_PATH = "/.well-known/est"
$TEST_DIR = Join-Path $repoRoot "tests\estclient"
$CA_CERT = "$TEST_DIR\chain.crt"
$CSR_FILE = "$TEST_DIR\etx.csr"
$CSR_DER = "$TEST_DIR\etx.csr.der"
$CERT_FILE = "$TEST_DIR\etx.crt.p7"
$CERT_PEM = "$TEST_DIR\etx.crt"
$KEY_FILE = "$TEST_DIR\etx.key"

# Create test directory if it doesn't exist
if (-not (Test-Path $TEST_DIR)) {
    New-Item -ItemType Directory -Path $TEST_DIR -Force | Out-Null
}


Write-Host "`n[*] Step 1: Get CA Certificates (CACerts)" -ForegroundColor Yellow
Write-Host "    Command: tools\curl.exe -v --cacert $CA_CHAIN_PATH --cert pki-https\pikachu_issued_https_localhost.crt --key pki-https\pikachu_issued_https.key $SERVER$EST_PATH/cacerts --output $CA_CERT" -ForegroundColor Gray
if (-not (Test-Path $CA_CHAIN_PATH)) {
    Write-Host "[-] CA chain file not found: $CA_CHAIN_PATH" -ForegroundColor Red
    exit 1
}
& tools\curl.exe -v --cacert $CA_CHAIN_PATH --cert pki-https\pikachu_issued_https_localhost.crt --key pki-https\pikachu_issued_https.key "$SERVER$EST_PATH/cacerts" --output $CA_CERT

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to get CA certificates" -ForegroundColor Red
    exit 1
}

if (Test-Path $CA_CERT) {
    Write-Host "[+] CA certificate saved to: $CA_CERT" -ForegroundColor Green
    $caSize = (Get-Item $CA_CERT).Length
    Write-Host "    Size: $caSize bytes" -ForegroundColor Gray
} else {
    Write-Host "[-] CA certificate file not created" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] Step 2: Generate Private Key" -ForegroundColor Yellow
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

# Generate dynamic CN: estclient-curl-mtls-hr:min:day:month:year
$now = Get-Date
$cn = "estclient-curl-mtls-$($now.Hour):$($now.Minute):$($now.Day):$($now.Month):$($now.Year)"

Write-Host "`n[*] Step 3: Generate Certificate Signing Request (CSR)" -ForegroundColor Yellow
Write-Host "    Command: openssl req -new -key $KEY_FILE -out $CSR_FILE -subj /CN=$cn" -ForegroundColor Gray

& openssl req -new -key $KEY_FILE -out $CSR_FILE -subj "/CN=$cn"

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to generate CSR" -ForegroundColor Red
    exit 1
}

if (Test-Path $CSR_FILE) {
    Write-Host "[+] CSR (PEM) saved to: $CSR_FILE" -ForegroundColor Green
    $csrSize = (Get-Item $CSR_FILE).Length
    Write-Host "    Size: $csrSize bytes" -ForegroundColor Gray
} else {
    Write-Host "[-] CSR file not created" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] Step 4: Convert CSR to DER format" -ForegroundColor Yellow
Write-Host "    Command: openssl req -in $CSR_FILE -outform DER -out $CSR_DER" -ForegroundColor Gray

& openssl req -in $CSR_FILE -outform DER -out $CSR_DER

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to convert CSR to DER" -ForegroundColor Red
    exit 1
}

if (Test-Path $CSR_DER) {
    Write-Host "[+] CSR (DER) saved to: $CSR_DER" -ForegroundColor Green
    $csrDerSize = (Get-Item $CSR_DER).Length
    Write-Host "    Size: $csrDerSize bytes" -ForegroundColor Gray
} else {
    Write-Host "[-] CSR DER file not created" -ForegroundColor Red
    exit 1
}


Write-Host "`n[*] Step 5: Enroll Certificate (Simple Enroll, mTLS)" -ForegroundColor Yellow
Write-Host "    Command: tools\curl.exe -v --cacert $CA_CHAIN_PATH --cert $TRUSTED_CERT --key $TRUSTED_KEY -X POST --data-binary @$CSR_DER $SERVER$EST_PATH/simpleenroll -H 'Content-Type: application/pkcs10' --output $CERT_FILE" -ForegroundColor Gray

& tools\curl.exe -v --cacert $CA_CHAIN_PATH --cert $TRUSTED_CERT --key $TRUSTED_KEY -X POST `
    --data-binary "@$CSR_DER" `
    "$SERVER$EST_PATH/simpleenroll" `
    -H "Content-Type: application/pkcs10" `
    --output $CERT_FILE

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to enroll certificate" -ForegroundColor Red
    exit 1
}

if (Test-Path $CERT_FILE) {
    Write-Host "[+] Certificate (PKCS#7) saved to: $CERT_FILE" -ForegroundColor Green
    $certSize = (Get-Item $CERT_FILE).Length
    Write-Host "    Size: $certSize bytes" -ForegroundColor Gray
} else {
    Write-Host "[-] Certificate file not created" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] Step 6: Decode base64 and extract certificate from PKCS#7" -ForegroundColor Yellow
Write-Host "    Command: openssl base64 -d -in $CERT_FILE -out ${CERT_FILE}.der && openssl pkcs7 -inform DER -in ${CERT_FILE}.der -print_certs -out $CERT_PEM" -ForegroundColor Gray

# Decode base64 to DER
& openssl base64 -d -in $CERT_FILE -out "${CERT_FILE}.der"

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to decode base64" -ForegroundColor Red
    exit 1
}

# Extract certificate from PKCS#7 DER
& openssl pkcs7 -inform DER -in "${CERT_FILE}.der" -print_certs -out $CERT_PEM

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Failed to extract certificate" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] Step 7: Verify Certificate" -ForegroundColor Yellow
Write-Host "    Command: openssl x509 -in $CERT_PEM -text -noout" -ForegroundColor Gray

& openssl x509 -in $CERT_PEM -text -noout | Select-Object -First 20

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[+] EST Enrollment mTLS Test Complete!" -ForegroundColor Green
    Write-Host "`nGenerated files:" -ForegroundColor Cyan
    Write-Host "  CA Certificate:    $CA_CERT" -ForegroundColor Gray
    Write-Host "  Private Key:       $KEY_FILE" -ForegroundColor Gray
    Write-Host "  CSR (PEM):         $CSR_FILE" -ForegroundColor Gray
    Write-Host "  CSR (DER):         $CSR_DER" -ForegroundColor Gray
    Write-Host "  Certificate (P7):  $CERT_FILE" -ForegroundColor Gray
    Write-Host "  Certificate (PEM): $CERT_PEM" -ForegroundColor Gray
} else {
    Write-Host "[-] Failed to verify certificate" -ForegroundColor Red
    exit 1
}
