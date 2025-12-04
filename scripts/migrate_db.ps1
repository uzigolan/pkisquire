# Database Migration Script
# Migrates the database schema to add any missing columns

Write-Host "=== Database Migration ===" -ForegroundColor Green
Write-Host ""

Write-Host "[*] Running database migration..." -ForegroundColor Cyan
.\.venv\Scripts\python.exe migrate_db.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Migration completed successfully!" -ForegroundColor Green
} else {
    Write-Host "[!] Migration failed with exit code $LASTEXITCODE" -ForegroundColor Red
}
Write-Host ""
