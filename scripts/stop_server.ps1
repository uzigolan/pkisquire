# Stop Flask Server Script
# Stops all running Flask server instances

Write-Host "=== Stopping Flask Server ===" -ForegroundColor Red
Write-Host ""

# Kill any existing Flask/Python processes running app.py
Write-Host "[*] Looking for Flask processes..." -ForegroundColor Cyan

$processes = Get-Process python -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*app.py*" -or $_.Path -like "*PKI*"
}

if ($processes) {
    Write-Host "[*] Found $($processes.Count) Flask process(es)" -ForegroundColor Yellow
    Write-Host "[*] Stopping processes..." -ForegroundColor Cyan
    
    $processes | ForEach-Object {
        Write-Host "    - PID: $($_.Id) | Path: $($_.Path)" -ForegroundColor Gray
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
    
    Start-Sleep -Seconds 2
    Write-Host "[+] Flask server stopped!" -ForegroundColor Green
} else {
    Write-Host "[!] No Flask processes found (server not running)" -ForegroundColor Yellow
}

Write-Host ""
