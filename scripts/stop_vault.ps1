# Stop HashiCorp Vault Server

$ErrorActionPreference = "Stop"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Stopping HashiCorp Vault Server" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

$VaultProcess = Get-Process -Name "vault" -ErrorAction SilentlyContinue

if (-not $VaultProcess) {
    Write-Host "OK: Vault is not running" -ForegroundColor Green
    exit 0
}

Write-Host "Found Vault process (PID: $($VaultProcess.Id))" -ForegroundColor Yellow
Write-Host "Stopping Vault..." -ForegroundColor Yellow

try {
    Stop-Process -Name "vault" -Force -ErrorAction Stop
    Start-Sleep -Seconds 2
    
    $StillRunning = Get-Process -Name "vault" -ErrorAction SilentlyContinue
    if ($StillRunning) {
        Write-Host "WARNING: Vault still running, forcing termination..." -ForegroundColor Yellow
        Stop-Process -Id $StillRunning.Id -Force
        Start-Sleep -Seconds 1
    }
    
    Write-Host "OK: Vault server stopped" -ForegroundColor Green
    
} catch {
    Write-Host "ERROR: Failed to stop Vault: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Vault server has been stopped." -ForegroundColor Green
