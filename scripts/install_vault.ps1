# Install HashiCorp Vault on Windows
# This script downloads and installs Vault to Program Files

param(
    [string]$Version = "1.15.4",
    [string]$InstallPath = "C:\Program Files\HashiCorp\Vault"
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "HashiCorp Vault Installer for Windows" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Host "Installing Vault version: $Version" -ForegroundColor Green
Write-Host "Install location: $InstallPath" -ForegroundColor Green
Write-Host ""

# Create installation directory
if (-not (Test-Path $InstallPath)) {
    Write-Host "Creating installation directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}

# Download Vault
$DownloadUrl = "https://releases.hashicorp.com/vault/${Version}/vault_${Version}_windows_amd64.zip"
$ZipFile = "$env:TEMP\vault_${Version}.zip"

Write-Host "Downloading Vault from: $DownloadUrl" -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipFile -UseBasicParsing
    Write-Host "[OK] Download complete" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to download Vault: $_" -ForegroundColor Red
    exit 1
}

# Extract Vault
Write-Host "Extracting Vault..." -ForegroundColor Yellow
try {
    Expand-Archive -Path $ZipFile -DestinationPath $InstallPath -Force
    Write-Host "[OK] Extraction complete" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to extract Vault: $_" -ForegroundColor Red
    exit 1
}

# Clean up zip file
Remove-Item $ZipFile -Force

# Add to System PATH if not already there
$VaultExe = "$InstallPath\vault.exe"
if (Test-Path $VaultExe) {
    Write-Host "[OK] Vault executable found: $VaultExe" -ForegroundColor Green
    
    # Get current system PATH
    $CurrentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    
    if ($CurrentPath -notlike "*$InstallPath*") {
        Write-Host "Adding Vault to system PATH..." -ForegroundColor Yellow
        $NewPath = "$CurrentPath;$InstallPath"
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")
        $env:Path = "$env:Path;$InstallPath"
        Write-Host "[OK] Vault added to system PATH" -ForegroundColor Green
    } else {
        Write-Host "[OK] Vault already in system PATH" -ForegroundColor Green
    }
} else {
    Write-Host "[ERROR] Vault executable not found!" -ForegroundColor Red
    exit 1
}

# Verify installation
Write-Host ""
Write-Host "Verifying installation..." -ForegroundColor Yellow
try {
    $VaultVersion = & $VaultExe version
    Write-Host "[OK] $VaultVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to run Vault: $_" -ForegroundColor Red
    exit 1
}

# Create data directory
$DataPath = "$InstallPath\data"
if (-not (Test-Path $DataPath)) {
    Write-Host "Creating data directory: $DataPath" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}

# Create config directory
$ConfigPath = "$InstallPath\config"
if (-not (Test-Path $ConfigPath)) {
    Write-Host "Creating config directory: $ConfigPath" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $ConfigPath -Force | Out-Null
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Close and reopen PowerShell to use 'vault' command" -ForegroundColor White
Write-Host "2. Run: .\scripts\start_vault.ps1 -Mode dev" -ForegroundColor White
Write-Host "   (Development mode for testing)" -ForegroundColor Gray
Write-Host "3. Or configure production mode with:" -ForegroundColor White
Write-Host "   .\scripts\start_vault.ps1 -Mode production" -ForegroundColor White
Write-Host ""
Write-Host "Vault installed to: $InstallPath" -ForegroundColor Cyan
Write-Host "Data directory: $DataPath" -ForegroundColor Cyan
Write-Host "Config directory: $ConfigPath" -ForegroundColor Cyan
