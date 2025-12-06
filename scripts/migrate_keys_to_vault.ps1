# migrate_keys_to_vault.ps1
# Migrates CA private keys and certificates from filesystem to HashiCorp Vault PKI engines

param(
    [switch]$DryRun = $false
)

Write-Host ""
Write-Host "=== Migrate CA Keys to Vault ===" -ForegroundColor Cyan
Write-Host ""

# Vault executable
$VaultExe = "C:\Program Files\HashiCorp\Vault\vault.exe"

if (-not (Test-Path $VaultExe)) {
    Write-Host "[ERROR] Vault executable not found at $VaultExe" -ForegroundColor Red
    Write-Host "Run install_vault.ps1 first" -ForegroundColor Yellow
    exit 1
}

# Check if Vault is running
try {
    $health = & $VaultExe status 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Vault is not running or not accessible" -ForegroundColor Red
        Write-Host "Run start_vault.ps1 first" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "[OK] Vault is running" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Cannot connect to Vault: $_" -ForegroundColor Red
    exit 1
}

# File paths
$RsaKeyPath = "pki-subca\rad_ca_sub_rsa.key"
$RsaCertPath = "pki-subca\rad_ca_sub_rsa.crt"
$RsaChainPath = "pki-subca\rad_chain_rsa.crt"

$EcKeyPath = "pki-subca\rad_ca_sub_ec.key"
$EcCertPath = "pki-subca\rad_ca_sub_ec.crt"
$EcChainPath = "pki-subca\rad_chain_ec.crt"

# Check files exist
Write-Host "Checking CA files..." -ForegroundColor Yellow

$files = @(
    $RsaKeyPath, $RsaCertPath, $RsaChainPath,
    $EcKeyPath, $EcCertPath, $EcChainPath
)

foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "  [OK] $file" -ForegroundColor Green
    } else {
        Write-Host "  [WARNING] $file not found" -ForegroundColor Yellow
    }
}

Write-Host ""

# Function to import CA into Vault PKI
function Import-CAToVault {
    param(
        [string]$PKIPath,
        [string]$KeyFile,
        [string]$CertFile,
        [string]$ChainFile,
        [string]$Name
    )
    
    Write-Host "[*] Importing $Name CA to Vault PKI: $PKIPath" -ForegroundColor Cyan
    
    if (-not (Test-Path $KeyFile)) {
        Write-Host "  [ERROR] Key file not found: $KeyFile" -ForegroundColor Red
        return $false
    }
    
    if (-not (Test-Path $CertFile)) {
        Write-Host "  [ERROR] Certificate file not found: $CertFile" -ForegroundColor Red
        return $false
    }
    
    # Read files
    $keyContent = Get-Content $KeyFile -Raw
    $certContent = Get-Content $CertFile -Raw
    
    # For chain, try to read it but it's optional
    $chainContent = ""
    if (Test-Path $ChainFile) {
        $chainContent = Get-Content $ChainFile -Raw
    }
    
    # Combine cert + chain if chain exists
    if ($chainContent) {
        $bundleContent = $certContent + "`n" + $chainContent
    } else {
        $bundleContent = $certContent
    }
    
    if ($DryRun) {
        Write-Host "  [DRY RUN] Would import:" -ForegroundColor Yellow
        Write-Host "    Key: $KeyFile" -ForegroundColor Gray
        Write-Host "    Cert: $CertFile" -ForegroundColor Gray
        Write-Host "    Chain: $ChainFile" -ForegroundColor Gray
        return $true
    }
    
    # Create temporary file with key + cert bundle
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        # Write key and certificate bundle
        $keyContent + "`n" + $bundleContent | Out-File -FilePath $tempFile -Encoding utf8 -NoNewline
        
        # Import to Vault
        Write-Host "  [*] Uploading CA bundle to Vault..." -ForegroundColor Yellow
        $result = & $VaultExe write "$PKIPath/config/ca" pem_bundle="@$tempFile" 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] CA imported successfully" -ForegroundColor Green
            
            # Verify by reading the CA certificate
            Write-Host "  [*] Verifying import..." -ForegroundColor Yellow
            $verify = & $VaultExe read -field=certificate "$PKIPath/cert/ca" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [OK] Verification successful" -ForegroundColor Green
                return $true
            } else {
                Write-Host "  [WARNING] Could not verify import: $verify" -ForegroundColor Yellow
                return $true
            }
        } else {
            Write-Host "  [ERROR] Failed to import CA: $result" -ForegroundColor Red
            return $false
        }
    } finally {
        # Clean up temp file
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
    }
}

# Import RSA CA
Write-Host ""
Write-Host "=== RSA CA Migration ===" -ForegroundColor Cyan
$rsaSuccess = Import-CAToVault `
    -PKIPath "pki-subca-rsa" `
    -KeyFile $RsaKeyPath `
    -CertFile $RsaCertPath `
    -ChainFile $RsaChainPath `
    -Name "RSA"

Write-Host ""
Write-Host "=== EC CA Migration ===" -ForegroundColor Cyan
$ecSuccess = Import-CAToVault `
    -PKIPath "pki-subca-ec" `
    -KeyFile $EcKeyPath `
    -CertFile $EcCertPath `
    -ChainFile $EcChainPath `
    -Name "EC"

Write-Host ""
Write-Host "=== Migration Summary ===" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "[DRY RUN] No changes made" -ForegroundColor Yellow
} else {
    if ($rsaSuccess) {
        Write-Host "[OK] RSA CA migrated successfully" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] RSA CA migration failed" -ForegroundColor Red
    }
    
    if ($ecSuccess) {
        Write-Host "[OK] EC CA migrated successfully" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] EC CA migration failed" -ForegroundColor Red
    }
    
    if ($rsaSuccess -and $ecSuccess) {
        Write-Host ""
        Write-Host "[SUCCESS] All CA keys migrated to Vault!" -ForegroundColor Green
        Write-Host "You can now sign certificates using Vault PKI" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Yellow
        Write-Host "  1. Restart the server: .\scripts\restart_server.ps1" -ForegroundColor Gray
        Write-Host "  2. Sign a certificate via /sign route" -ForegroundColor Gray
        Write-Host "  3. Check logs for 'VAULT MODE' messages" -ForegroundColor Gray
    }
}

Write-Host ""
