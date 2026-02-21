# Initialize Vault PKI Engines for pkisquire CA

param(
    [Parameter(Mandatory=$true)]
    [string]$RootToken,
    
    [string]$VaultAddr = "http://127.0.0.1:8200"
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Initializing Vault PKI for pkisquire CA" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Set Vault address and token
$env:VAULT_ADDR = $VaultAddr
$env:VAULT_TOKEN = $RootToken

Write-Host "Vault Address: $VaultAddr" -ForegroundColor Green
Write-Host ""

# Verify Vault is accessible
Write-Host "Checking Vault status..." -ForegroundColor Yellow
try {
    vault status | Out-Null
    Write-Host "OK: Vault is accessible" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Cannot connect to Vault at $VaultAddr" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Step 1: Enable PKI Secrets Engines" -ForegroundColor Cyan
Write-Host "-----------------------------------" -ForegroundColor Cyan

# Enable RSA PKI engine
Write-Host "Enabling pki-subca-rsa..." -ForegroundColor Yellow
vault secrets enable -path=pki-subca-rsa pki 2>&1 | Out-Null
Write-Host "OK: pki-subca-rsa enabled" -ForegroundColor Green

# Enable EC PKI engine
Write-Host "Enabling pki-subca-ec..." -ForegroundColor Yellow
vault secrets enable -path=pki-subca-ec pki 2>&1 | Out-Null
Write-Host "OK: pki-subca-ec enabled" -ForegroundColor Green

Write-Host ""
Write-Host "Step 2: Configure PKI Max Lease TTL" -ForegroundColor Cyan
Write-Host "-----------------------------------" -ForegroundColor Cyan

Write-Host "Configuring pki-subca-rsa max TTL (10 years)..." -ForegroundColor Yellow
vault secrets tune -max-lease-ttl=87600h pki-subca-rsa 2>&1 | Out-Null
Write-Host "OK: pki-subca-rsa configured" -ForegroundColor Green

Write-Host "Configuring pki-subca-ec max TTL (10 years)..." -ForegroundColor Yellow
vault secrets tune -max-lease-ttl=87600h pki-subca-ec 2>&1 | Out-Null
Write-Host "OK: pki-subca-ec configured" -ForegroundColor Green

Write-Host ""
Write-Host "Step 3: Create PKI Roles" -ForegroundColor Cyan
Write-Host "------------------------" -ForegroundColor Cyan

Write-Host "Creating roles for RSA PKI..." -ForegroundColor Yellow
vault write pki-subca-rsa/roles/scep-enrollment allowed_domains="*" allow_subdomains=true allow_bare_domains=true allow_any_name=true allow_ip_sans=true max_ttl=8760h ttl=8760h key_type=rsa key_bits=2048 2>&1 | Out-Null
vault write pki-subca-rsa/roles/est-enrollment allowed_domains="*" allow_subdomains=true allow_bare_domains=true allow_any_name=true allow_ip_sans=true max_ttl=8760h ttl=8760h key_type=rsa key_bits=2048 2>&1 | Out-Null
vault write pki-subca-rsa/roles/server-cert allowed_domains="*" allow_subdomains=true allow_bare_domains=true allow_any_name=true allow_ip_sans=true server_flag=true client_flag=true max_ttl=8760h ttl=8760h key_type=rsa key_bits=2048 2>&1 | Out-Null
Write-Host "OK: RSA roles created (scep-enrollment, est-enrollment, server-cert)" -ForegroundColor Green

Write-Host "Creating roles for EC PKI..." -ForegroundColor Yellow
vault write pki-subca-ec/roles/scep-enrollment allowed_domains="*" allow_subdomains=true allow_bare_domains=true allow_any_name=true allow_ip_sans=true max_ttl=8760h ttl=8760h key_type=ec key_bits=256 2>&1 | Out-Null
vault write pki-subca-ec/roles/est-enrollment allowed_domains="*" allow_subdomains=true allow_bare_domains=true allow_any_name=true allow_ip_sans=true max_ttl=8760h ttl=8760h key_type=ec key_bits=256 2>&1 | Out-Null
vault write pki-subca-ec/roles/server-cert allowed_domains="*" allow_subdomains=true allow_bare_domains=true allow_any_name=true allow_ip_sans=true server_flag=true client_flag=true max_ttl=8760h ttl=8760h key_type=ec key_bits=256 2>&1 | Out-Null
Write-Host "OK: EC roles created (scep-enrollment, est-enrollment, server-cert)" -ForegroundColor Green

Write-Host ""
Write-Host "Step 4: Enable Transit Secrets Engine" -ForegroundColor Cyan
Write-Host "-------------------------------------" -ForegroundColor Cyan

Write-Host "Enabling transit engine..." -ForegroundColor Yellow
vault secrets enable transit 2>&1 | Out-Null
Write-Host "OK: transit engine enabled" -ForegroundColor Green

Write-Host "Creating OCSP signing key..." -ForegroundColor Yellow
vault write -f transit/keys/ocsp-signing type=rsa-2048 2>&1 | Out-Null
Write-Host "OK: OCSP signing key created" -ForegroundColor Green

Write-Host ""
Write-Host "Step 5: Enable AppRole Authentication" -ForegroundColor Cyan
Write-Host "-------------------------------------" -ForegroundColor Cyan

Write-Host "Enabling approle auth..." -ForegroundColor Yellow
vault auth enable approle 2>&1 | Out-Null
Write-Host "OK: approle auth enabled" -ForegroundColor Green

Write-Host ""
Write-Host "Step 6: Create AppRole Policy" -ForegroundColor Cyan
Write-Host "-----------------------------" -ForegroundColor Cyan

$PolicyContent = @'
path "pki-subca-rsa/sign/*" { capabilities = ["create", "update"] }
path "pki-subca-rsa/issue/*" { capabilities = ["create", "update"] }
path "pki-subca-rsa/ca/pem" { capabilities = ["read"] }
path "pki-subca-rsa/ca_chain" { capabilities = ["read"] }
path "pki-subca-rsa/crl/pem" { capabilities = ["read"] }
path "pki-subca-ec/sign/*" { capabilities = ["create", "update"] }
path "pki-subca-ec/issue/*" { capabilities = ["create", "update"] }
path "pki-subca-ec/ca/pem" { capabilities = ["read"] }
path "pki-subca-ec/ca_chain" { capabilities = ["read"] }
path "pki-subca-ec/crl/pem" { capabilities = ["read"] }
path "transit/sign/ocsp-signing" { capabilities = ["create", "update"] }
path "transit/verify/ocsp-signing" { capabilities = ["create", "update"] }
'@

$PolicyFile = "$env:TEMP\pkisquire-ca-policy.hcl"
Set-Content -Path $PolicyFile -Value $PolicyContent -Encoding UTF8

Write-Host "Creating pkisquire-ca policy..." -ForegroundColor Yellow
vault policy write pkisquire-ca $PolicyFile 2>&1 | Out-Null
Write-Host "OK: pkisquire-ca policy created" -ForegroundColor Green

Remove-Item $PolicyFile -Force

Write-Host ""
Write-Host "Step 7: Create AppRole" -ForegroundColor Cyan
Write-Host "----------------------" -ForegroundColor Cyan

Write-Host "Creating pkisquire-ca AppRole..." -ForegroundColor Yellow
vault write auth/approle/role/pkisquire-ca token_policies="pkisquire-ca" token_ttl=1h token_max_ttl=24h secret_id_ttl=0 secret_id_num_uses=0 2>&1 | Out-Null
Write-Host "OK: pkisquire-ca AppRole created" -ForegroundColor Green

Write-Host ""
Write-Host "Step 8: Get AppRole Credentials" -ForegroundColor Cyan
Write-Host "-------------------------------" -ForegroundColor Cyan

$RoleIdOutput = vault read -field=role_id auth/approle/role/pkisquire-ca/role-id
$SecretIdOutput = vault write -field=secret_id -f auth/approle/role/pkisquire-ca/secret-id

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Vault PKI Initialization Complete!" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "SAVE THESE CREDENTIALS:" -ForegroundColor Yellow
Write-Host ""
Write-Host "Role ID:" -ForegroundColor Cyan
Write-Host $RoleIdOutput -ForegroundColor White
Write-Host ""
Write-Host "Secret ID:" -ForegroundColor Cyan
Write-Host $SecretIdOutput -ForegroundColor White
Write-Host ""
Write-Host "Set environment variables:" -ForegroundColor Yellow
Write-Host "`$env:VAULT_ROLE_ID = `"$RoleIdOutput`"" -ForegroundColor Gray
Write-Host "`$env:VAULT_SECRET_ID = `"$SecretIdOutput`"" -ForegroundColor Gray
Write-Host ""
Write-Host "Next: .\scripts\migrate_keys_to_vault.ps1" -ForegroundColor Yellow

