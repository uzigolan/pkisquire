# Start HashiCorp Vault Server
# Supports both development mode (for testing) and production mode

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("dev", "production")]
    [string]$Mode = "dev",
    
    [string]$VaultPath = "C:\Program Files\HashiCorp\Vault",
    [string]$Address = "127.0.0.1:8200",
    [string]$ConfigFile = ""
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Starting HashiCorp Vault Server" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Check if Vault is installed
$VaultExe = "$VaultPath\vault.exe"
if (-not (Test-Path $VaultExe)) {
    Write-Host "ERROR: Vault not found at: $VaultExe" -ForegroundColor Red
    Write-Host "Run: .\scripts\install_vault.ps1" -ForegroundColor Yellow
    exit 1
}

# Check if Vault is already running
$VaultProcess = Get-Process -Name "vault" -ErrorAction SilentlyContinue
if ($VaultProcess) {
    Write-Host "WARNING: Vault is already running (PID: $($VaultProcess.Id))" -ForegroundColor Yellow
    Write-Host "Stop it first with: .\scripts\stop_vault.ps1" -ForegroundColor Yellow
    exit 1
}

Write-Host "Mode: $Mode" -ForegroundColor Green
Write-Host "Address: $Address" -ForegroundColor Green
Write-Host ""

if ($Mode -eq "dev") {
    # Development mode - simple, insecure, in-memory
    Write-Host "Starting Vault in DEVELOPMENT mode..." -ForegroundColor Yellow
    Write-Host "WARNING: This mode is NOT secure and should only be used for testing!" -ForegroundColor Red
    Write-Host ""
    
    # Set environment variable for Vault address
    $env:VAULT_ADDR = "http://$Address"
    [Environment]::SetEnvironmentVariable("VAULT_ADDR", "http://$Address", "User")
    
    Write-Host "Starting Vault server..." -ForegroundColor Yellow
    Write-Host "Root Token will be displayed below - SAVE IT!" -ForegroundColor Yellow
    Write-Host ""
    
    # Start Vault in dev mode (this will block and show output)
    & $VaultExe server -dev "-dev-listen-address=$Address"
    
} else {
    # Production mode - requires configuration file
    Write-Host "Starting Vault in PRODUCTION mode..." -ForegroundColor Yellow
    
    if (-not $ConfigFile) {
        $ConfigFile = "$VaultPath\config\vault-config.hcl"
    }
    
    if (-not (Test-Path $ConfigFile)) {
        Write-Host "ERROR: Config file not found: $ConfigFile" -ForegroundColor Red
        Write-Host ""
        Write-Host "Creating default production config..." -ForegroundColor Yellow
        
        # Create default config
        $ConfigDir = Split-Path $ConfigFile -Parent
        if (-not (Test-Path $ConfigDir)) {
            New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
        }
        
        $DefaultConfig = @"
# Vault Production Configuration

storage "file" {
  path = "$($VaultPath -replace '\\', '\\')\data"
}

listener "tcp" {
  address     = "$Address"
  tls_disable = 1
}

ui = true
api_addr = "http://$Address"
cluster_addr = "http://127.0.0.1:8201"
disable_mlock = true
log_level = "info"
"@
        Set-Content -Path $ConfigFile -Value $DefaultConfig -Encoding UTF8
        Write-Host "OK: Created config: $ConfigFile" -ForegroundColor Green
        Write-Host ""
    }
    
    Write-Host "Using config: $ConfigFile" -ForegroundColor Green
    Write-Host ""
    
    # Set environment variable for Vault address
    $env:VAULT_ADDR = "http://$Address"
    [Environment]::SetEnvironmentVariable("VAULT_ADDR", "http://$Address", "User")
    
    Write-Host "Starting Vault server..." -ForegroundColor Yellow
    Write-Host "After first start, run: vault operator init" -ForegroundColor Yellow
    Write-Host ""
    
    # Start Vault in production mode
    & $VaultExe server -config=$ConfigFile
}
