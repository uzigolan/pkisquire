# Restart Flask Server Script
# Stops any running Flask instances and starts fresh

Write-Host "=== Restarting Flask Server ===" -ForegroundColor Green
Write-Host ""

# Kill any existing Flask/Python processes running app.py
Write-Host "[*] Stopping existing Flask processes..." -ForegroundColor Cyan
Get-Process python -ErrorAction SilentlyContinue | Where-Object {$_.CommandLine -like "*app.py*"} | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Start the server
Write-Host "[*] Starting Flask server on port 8090..." -ForegroundColor Cyan
$env:PATH = "C:\Program Files\OpenSSL-Win64\bin;" + $env:PATH
Start-Process -NoNewWindow -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "app.py"

Write-Host "[+] Server started!" -ForegroundColor Green
Write-Host "    SCEP endpoint: http://localhost:8090/scep" -ForegroundColor Yellow
Write-Host "    Web UI: https://localhost:5000" -ForegroundColor Yellow
Write-Host ""
