# Restart Flask Server Script (with Log Clearing)
# Stops any running Flask instances, clears the log file, and starts fresh

Write-Host "=== Restarting Flask Server (Clear Log) ===" -ForegroundColor Green
Write-Host ""

# Kill any existing Flask/Python processes running app.py
Write-Host "[*] Stopping existing Flask processes..." -ForegroundColor Cyan
Get-Process python -ErrorAction SilentlyContinue | Where-Object {$_.CommandLine -like "*app.py*"} | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Clear Python cache to avoid stale .pyc files
Write-Host "[*] Clearing Python cache..." -ForegroundColor Cyan
Remove-Item -Recurse -Force __pycache__ -ErrorAction SilentlyContinue

# Clear the log file (read from config.ini)
Write-Host "[*] Clearing log file..." -ForegroundColor Cyan
$configFile = "config.ini"
$logFile = "logs\server.log"  # default

if (Test-Path $configFile) {
    $content = Get-Content $configFile -Raw
    if ($content -match '(?ms)\[LOGGING\].*?log_file\s*=\s*(.+?)(\r?\n|$)') {
        $logFile = $matches[1].Trim()
        Write-Host "[*] Found log_file in config.ini: $logFile" -ForegroundColor Cyan
    }
}

if (Test-Path $logFile) {
    Clear-Content $logFile
    Write-Host "[+] Log file cleared: $logFile" -ForegroundColor Green
} else {
    Write-Host "[!] Log file not found: $logFile" -ForegroundColor Yellow
}

# Start the server
Write-Host "[*] Starting Flask server on port 8090..." -ForegroundColor Cyan
$env:PATH = "C:\Program Files\OpenSSL-Win64\bin;" + $env:PATH
$env:VAULT_ROLE_ID = "99e58006-875b-9d19-a591-1d69dcebea15"
$env:VAULT_SECRET_ID = "a30235f6-3cd1-7080-d25a-bba644933d48"
$env:VAULT_ADDR = "http://127.0.0.1:8200"

# Start in background using Start-Job to preserve environment variables
Start-Job -Name "FlaskServer" -ScriptBlock {
    param($path, $vaultRole, $vaultSecret, $vaultAddr)
    Set-Location $path
    $env:PATH = "C:\Program Files\OpenSSL-Win64\bin;" + $env:PATH
    $env:VAULT_ROLE_ID = $vaultRole
    $env:VAULT_SECRET_ID = $vaultSecret
    $env:VAULT_ADDR = $vaultAddr
    & .\.venv\Scripts\python.exe app.py
} -ArgumentList (Get-Location), $env:VAULT_ROLE_ID, $env:VAULT_SECRET_ID, $env:VAULT_ADDR | Out-Null

Start-Sleep -Seconds 3

Write-Host "[+] Server started!" -ForegroundColor Green
Write-Host "    SCEP endpoint: http://localhost:8090/scep" -ForegroundColor Yellow
Write-Host "    Web UI: https://localhost:5000" -ForegroundColor Yellow
Write-Host ""
