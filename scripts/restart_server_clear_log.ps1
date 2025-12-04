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
Start-Process -NoNewWindow -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "app.py"

Write-Host "[+] Server started!" -ForegroundColor Green
Write-Host "    SCEP endpoint: http://localhost:8090/scep" -ForegroundColor Yellow
Write-Host "    Web UI: https://localhost:5000" -ForegroundColor Yellow
Write-Host ""
