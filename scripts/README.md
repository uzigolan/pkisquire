# Server Management Scripts

This directory contains PowerShell scripts for managing the PKI Flask server and database.

## Quick Start Guide

### Complete Workflow (Vault Mode)

**Step 1: Start Vault Server** (if not already running)
```powershell
# Check if Vault is running
Get-Process vault -ErrorAction SilentlyContinue

# If not running, start Vault in dev mode (for development/testing)
# Open a new PowerShell window and run:
vault server -dev

# Keep this window open - Vault needs to stay running
```

**Step 2: Start PKI Server**
```powershell
# Navigate to PKI project directory
cd C:\Users\uzi\Downloads\projects\PKI

# Start server with clean logs (recommended)
.\scripts\restart_server_clear_log.ps1

# The script will:
# - Stop any running Flask servers
# - Clear Python cache
# - Clear log file
# - Set Vault credentials automatically
# - Start Flask server in background
```

**Step 3: Verify Server is Running**
```powershell
# Check server startup logs
Get-Content logs\server.log | Select-Object -First 20

# Look for these lines:
# ✓ "Vault integration is ENABLED"
# ✓ "Authenticated with Vault"
# ✓ "Vault client connected"
# ✓ "Running in VAULT MODE - keys isolated in Vault"
```

**Step 4: Access the Web UI**
```powershell
# Open browser to:
# https://localhost:443 (main UI)
# or
# https://localhost:5000 (alternative port)

# Or test with curl:
curl.exe https://localhost/about -k
```

**Step 5: Sign a Certificate (Test Vault)**
```powershell
# 1. Access web UI: https://localhost/sign
# 2. Upload a CSR or generate one
# 3. Submit for signing
# 4. Check logs to verify Vault was used:

Get-Content logs\server.log | Select-String "VAULT MODE"

# Expected output:
# INFO [ca] 🔐 VAULT MODE: Signing CSR via Vault PKI engine
# DEBUG [ca]   → PKI Path: pki-subca-ec (or pki-subca-rsa)
# DEBUG [ca]   → Role: server-cert
```

**Step 6: Stop Server (when done)**
```powershell
.\scripts\stop_server.ps1

# To also stop Vault (in the Vault terminal window):
# Press Ctrl+C
```

---

### Simple Workflow (Without Vault - Legacy Mode)

If you want to use file-based keys instead of Vault:

**Step 1: Disable Vault in config.ini**
```ini
[VAULT]
enabled = false
```

**Step 2: Start Server**
```powershell
.\scripts\restart_server_clear_log.ps1
```

**Step 3: Verify Legacy Mode**
```powershell
Get-Content logs\server.log | Select-String "LEGACY MODE"

# Expected output:
# INFO [app] Falling back to LEGACY MODE - using file-based keys
```

---

### Daily Development Workflow

```powershell
# Morning - Start everything
vault server -dev              # Terminal 1 (keep open)
.\scripts\restart_server_clear_log.ps1  # Terminal 2

# During development - Quick restarts after code changes
.\scripts\restart_server.ps1   # Keeps logs, faster restart

# Testing - Fresh start with clean logs
.\scripts\restart_server_clear_log.ps1

# Check logs frequently
Get-Content logs\server.log -Tail 20

# End of day - Cleanup
.\scripts\stop_server.ps1      # Stop Flask
# Ctrl+C in Vault terminal     # Stop Vault
```

---

## Available Scripts

### Server Management

#### `stop_server.ps1`
**Purpose:** Stop all running Flask server instances.

**Usage:**
```powershell
.\scripts\stop_server.ps1
```

**What it does:**
- Searches for Python processes running `app.py`
- Displays found processes (PID and path)
- Stops all Flask server processes
- Reports if no server is running

**When to use:**
- Stopping the server before database migration
- Shutting down after debugging
- Cleaning up stuck processes
- Before switching server configurations

---

#### `run_server.ps1`
**Purpose:** Start the Flask server with OpenSSL in PATH.

**Usage:**
```powershell
.\scripts\run_server.ps1
```

**What it does:**
- Adds OpenSSL to PATH environment variable
- Launches Flask server using virtual environment Python
- Runs in the current terminal window

**When to use:** 
- First time starting the server
- Running server in foreground for debugging
- When you need to see live server output

---

#### `restart_server.ps1`
**Purpose:** Restart the Flask server without clearing logs.

**Usage:**
```powershell
.\scripts\restart_server.ps1
```

**What it does:**
1. Stops all running Python processes with `app.py`
2. Clears Python cache (`__pycache__`)
3. Sets Vault environment variables (VAULT_ROLE_ID, VAULT_SECRET_ID, VAULT_ADDR)
4. Starts Flask server in background using PowerShell job
5. Displays server endpoints (SCEP on 8090, Web UI on 5000)

**When to use:**
- Quick server restart after code changes
- Keeping existing logs for debugging
- Running server in background with Vault support

**Note:** If Vault is enabled in `config.ini` ([VAULT] enabled=true), this script automatically configures the necessary credentials.

---

#### `restart_server_clear_log.ps1` ⭐ **Recommended**
**Purpose:** Restart the Flask server and clear the log file.

**Usage:**
```powershell
.\scripts\restart_server_clear_log.ps1
```

**What it does:**
1. Stops all running Python processes with `app.py`
2. Clears Python cache (`__pycache__`)
3. Reads log file path from `config.ini` (defaults to `logs\server.log`)
4. Clears the log file (fresh start)
5. Sets Vault environment variables (VAULT_ROLE_ID, VAULT_SECRET_ID, VAULT_ADDR)
6. Starts Flask server in background using PowerShell job
7. Displays server endpoints

**When to use:** ⭐ **Use this for most scenarios**
- Testing after configuration changes
- Starting fresh debugging session
- Before running test suites
- Removing old log entries
- Testing Vault mode functionality

**Note:** If Vault is enabled in `config.ini` ([VAULT] enabled=true), this script automatically configures the necessary credentials.

---

### Database Management

#### `migrate_db.ps1`
**Purpose:** Migrate database schema to add missing columns.

**Usage:**
```powershell
.\scripts\migrate_db.ps1
```

**What it does:**
- Runs `migrate_db.py` using virtual environment Python
- Adds missing columns to existing database tables
- Safe to run multiple times (idempotent)
- Reports success or failure status

**When to use:**
- After updating database schema in code
- Migrating from older database versions
- Adding new features that require schema changes
- Initial setup of existing database files

---

### Vault Integration

#### Overview
The PKI server supports **HashiCorp Vault** for secure CA key isolation. When enabled, private keys are stored in Vault's PKI engine instead of the filesystem, providing enhanced security through:
- Key isolation (keys never leave Vault)
- Access control and audit logging
- Centralized key management

#### Configuration

**1. Enable Vault in `config.ini`:**
```ini
[VAULT]
enabled = true
address = http://127.0.0.1:8200
pki_rsa_path = pki-subca-rsa
pki_ec_path = pki-subca-ec
```

**2. Vault Credentials:**
The restart scripts automatically set these environment variables:
- `VAULT_ROLE_ID` - AppRole role ID for authentication
- `VAULT_SECRET_ID` - AppRole secret ID for authentication
- `VAULT_ADDR` - Vault server address

**Current credentials (configured in restart scripts):**
```
VAULT_ROLE_ID: 99e58006-875b-9d19-a591-1d69dcebea15
VAULT_SECRET_ID: a30235f6-3cd1-7080-d25a-bba644933d48
VAULT_ADDR: http://127.0.0.1:8200
```

#### Using Vault Mode

**Starting Server with Vault:**
```powershell
# Restart with Vault credentials (recommended)
.\scripts\restart_server_clear_log.ps1

# Or quick restart
.\scripts\restart_server.ps1
```

The scripts automatically:
1. Set required Vault environment variables
2. Connect to Vault using AppRole authentication
3. Use Vault PKI engines for certificate signing

**Verifying Vault Mode:**
Check the server logs after startup:
```powershell
Get-Content logs\server.log | Select-String "Vault"
```

Expected output:
```
INFO [app] Vault integration is ENABLED (config.ini [VAULT] enabled=true)
INFO [vault_client] Authenticated with Vault at http://127.0.0.1:8200
INFO [app] ✓ Vault client connected to http://127.0.0.1:8200
INFO [app]   RSA PKI path: pki-subca-rsa
INFO [app]   EC PKI path: pki-subca-ec
INFO [app] Running in VAULT MODE - keys isolated in Vault
```

**Checking Signing Operations:**
When signing certificates, logs will show:
```
INFO [ca] 🔐 VAULT MODE: Signing CSR via Vault PKI engine
DEBUG [ca]   → PKI Path: pki-subca-ec
DEBUG [ca]   → Role: server-cert
DEBUG [ca]   → TTL: 8760h
```

#### Vault Setup (One-Time)

**If you need to recreate Vault credentials:**

1. **Enable AppRole authentication:**
```powershell
$env:VAULT_ADDR = "http://127.0.0.1:8200"
& "C:\Program Files\HashiCorp\Vault\vault.exe" auth enable approle
```

2. **Create PKI policy:**
```powershell
$policy = @"
path "pki-subca-rsa/sign/*" {
  capabilities = ["create", "update"]
}
path "pki-subca-ec/sign/*" {
  capabilities = ["create", "update"]
}
path "pki-subca-rsa/issue/*" {
  capabilities = ["create", "update"]
}
path "pki-subca-ec/issue/*" {
  capabilities = ["create", "update"]
}
path "pki-subca-rsa/cert/ca" {
  capabilities = ["read"]
}
path "pki-subca-ec/cert/ca" {
  capabilities = ["read"]
}
"@

$policy | & "C:\Program Files\HashiCorp\Vault\vault.exe" policy write pki-app -
```

3. **Create AppRole:**
```powershell
& "C:\Program Files\HashiCorp\Vault\vault.exe" write auth/approle/role/pki-app `
  token_policies="pki-app" `
  token_ttl=1h `
  token_max_ttl=4h
```

4. **Get credentials:**
```powershell
# Get role_id
& "C:\Program Files\HashiCorp\Vault\vault.exe" read -field=role_id auth/approle/role/pki-app/role-id

# Generate secret_id
& "C:\Program Files\HashiCorp\Vault\vault.exe" write -field=secret_id -force auth/approle/role/pki-app/secret-id
```

5. **Update restart scripts:**
Edit `scripts\restart_server.ps1` and `scripts\restart_server_clear_log.ps1` with the new credentials.

#### Switching Between RSA and EC Mode

The PKI server supports dual CA modes (RSA and EC). To switch:

**1. Edit `config.ini`:**
```ini
[CA]
mode = EC    # or "RSA"
```

**2. Restart server:**
```powershell
.\scripts\restart_server_clear_log.ps1
```

**3. Verify mode:**
```powershell
# Check web UI navbar - should show "CA (EC)" or "CA (RSA)"
curl.exe https://localhost/about -k | Select-String "CA \("

# Check logs
Get-Content logs\server.log | Select-String "CA_MODE"
```

When using Vault:
- **RSA mode** uses `pki-subca-rsa` Vault engine
- **EC mode** uses `pki-subca-ec` Vault engine

#### Troubleshooting Vault

**Permission Denied Error:**
```
ERROR [vault_client] Failed to sign CSR with Vault: permission denied
```
**Solution:** Ensure the AppRole has the correct policy (see Vault Setup above)

**Authentication Failed:**
```
ERROR [app] Failed to initialize Vault: VAULT_ROLE_ID and VAULT_SECRET_ID must be set
```
**Solution:** Restart scripts should set these automatically. If manually running `python app.py`:
```powershell
$env:VAULT_ROLE_ID = "99e58006-875b-9d19-a591-1d69dcebea15"
$env:VAULT_SECRET_ID = "a30235f6-3cd1-7080-d25a-bba644933d48"
$env:VAULT_ADDR = "http://127.0.0.1:8200"
python app.py
```

**Vault Not Running:**
```
ERROR [app] Failed to initialize Vault: connection refused
```
**Solution:** Start Vault server:
```powershell
# Dev mode (for testing)
vault server -dev

# Or check if Vault is running
Get-Process vault
```

**Legacy Fallback:**
If Vault connection fails, the server automatically falls back to legacy mode (file-based keys):
```
INFO [app] Falling back to LEGACY MODE - using file-based keys
```

---

## Quick Reference

| Task | Command | Notes |
|------|---------|-------|
| Stop server | `.\scripts\stop_server.ps1` | Gracefully stop all instances |
| Start server | `.\scripts\run_server.ps1` | Foreground, see live output |
| Restart server | `.\scripts\restart_server.ps1` | Background, keep logs, **Vault enabled** |
| Fresh restart | `.\scripts\restart_server_clear_log.ps1` | **Recommended** - Clean start, **Vault enabled** |
| Migrate database | `.\scripts\migrate_db.ps1` | After schema updates |
| Check Vault status | `Get-Content logs\server.log \| Select-String "Vault"` | Verify Vault connection |
| Switch CA mode | Edit `config.ini` [CA] mode, then restart | RSA or EC |

---

## Quick Reference

| Task | Command | Notes |
|------|---------|-------|
| Stop server | `.\scripts\stop_server.ps1` | Gracefully stop all instances |
| Start server | `.\scripts\run_server.ps1` | Foreground, see live output |
| Restart server | `.\scripts\restart_server.ps1` | Background, keep logs |
| Fresh restart | `.\scripts\restart_server_clear_log.ps1` | **Recommended** - Clean start |
| Migrate database | `.\scripts\migrate_db.ps1` | After schema updates |

## Common Workflows

### Testing Workflow (Recommended)
```powershell
# 1. Restart server with clean logs (Vault enabled)
.\scripts\restart_server_clear_log.ps1

# 2. Verify Vault mode is active
Get-Content logs\server.log | Select-String "Vault"

# 3. Run tests
.\tests\scripts\test_sscep.ps1
.\tests\scripts\test_estclient_curl.ps1
.\tests\scripts\test_ocsp.ps1

# 4. Check logs for signing operations
Get-Content logs\server.log | Select-String "VAULT MODE|LEGACY MODE"

# 5. Review any issues
Get-Content logs\server.log -Tail 50
```

### Development Workflow
```powershell
# 1. Make code changes
# ... edit app.py, models.py, ca.py, etc. ...

# 2. Restart server to apply changes (Vault enabled)
.\scripts\restart_server.ps1

# 3. Test your changes
# ... use web UI or API ...

# 4. If issues, restart with clean log
.\scripts\restart_server_clear_log.ps1

# 5. Check logs for errors
Get-Content logs\server.log | Select-String "ERROR|WARNING"
```

### Vault Testing Workflow
```powershell
# 1. Ensure Vault is running
Get-Process vault

# 2. Restart server with Vault mode
.\scripts\restart_server_clear_log.ps1

# 3. Verify Vault connection
Get-Content logs\server.log | Select-String "Vault client connected"

# 4. Sign a certificate via web UI (/sign)

# 5. Check signing used Vault (not legacy)
Get-Content logs\server.log | Select-String "VAULT MODE: Signing CSR"

# Expected output:
# INFO [ca] 🔐 VAULT MODE: Signing CSR via Vault PKI engine
# DEBUG [ca]   → PKI Path: pki-subca-ec (or pki-subca-rsa)
```

### Switching CA Mode (RSA ↔ EC)
```powershell
# 1. Stop server
.\scripts\stop_server.ps1

# 2. Edit config.ini [CA] mode
# Change: mode = EC  (or mode = RSA)

# 3. Restart with clean logs
.\scripts\restart_server_clear_log.ps1

# 4. Verify mode change
curl.exe https://localhost/about -k | Select-String "CA \("
# Should show: CA (EC) or CA (RSA)

# 5. Verify Vault using correct PKI engine
Get-Content logs\server.log | Select-String "PKI Path: pki-subca"
# Should show: pki-subca-ec (EC mode) or pki-subca-rsa (RSA mode)
```

### Database Migration Workflow
```powershell
# 1. Stop server
.\scripts\stop_server.ps1

# 2. Backup database (optional but recommended)
Copy-Item db\certs.db db\certs.db.backup

# 3. Run migration
.\scripts\migrate_db.ps1

# 4. Start server
.\scripts\run_server.ps1
```

## Script Details

### Environment Requirements
All scripts assume:
- Virtual environment at `.\.venv\` (Python 3.12+)
- OpenSSL installed at `C:\Program Files\OpenSSL-Win64\bin\`
- Working directory is the PKI project root
- Configuration file at `config.ini`
- **HashiCorp Vault** (optional, for Vault mode):
  - Vault server running at `http://127.0.0.1:8200` (or as configured)
  - AppRole authentication enabled
  - PKI engines mounted at `pki-subca-rsa` and `pki-subca-ec`
  - Restart scripts automatically set Vault credentials

### Server Endpoints
After starting the server, these endpoints are available:

- **SCEP**: `http://localhost:8090/scep`
- **EST**: `https://localhost:443/.well-known/est/`
- **OCSP**: `http://localhost:80/ocsp`
- **Web UI**: `https://localhost:5000` (or as configured)

### Process Management
The restart scripts use:
```powershell
Get-Process python | Where-Object {$_.CommandLine -like "*app.py*"} | Stop-Process -Force
```
This ensures only the Flask server process is stopped, not other Python processes.

### Background Execution
Both restart scripts use:
```powershell
Start-Process -NoNewWindow -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "app.py"
```
This runs the server in the background without opening a new window.

## Troubleshooting

### Complete Workflow Issues

**Problem: "vault: command not found"**
```powershell
# Solution: Add Vault to PATH or use full path
& "C:\Program Files\HashiCorp\Vault\vault.exe" server -dev

# Or permanently add to PATH:
$env:PATH = "C:\Program Files\HashiCorp\Vault;" + $env:PATH
```

**Problem: "Vault server already running on :8200"**
```powershell
# Check if Vault is already running
Get-Process vault

# If running, either:
# 1. Use the existing Vault server (preferred)
# 2. Or stop it first:
Get-Process vault | Stop-Process -Force
```

**Problem: Server starts but shows "LEGACY MODE" instead of "VAULT MODE"**
```powershell
# Check Vault is running
Get-Process vault

# Check Vault is accessible
curl http://127.0.0.1:8200/v1/sys/health

# Check config.ini has Vault enabled
Get-Content config.ini | Select-String -Pattern "^\[VAULT\]" -Context 0,5

# Restart server with clean logs
.\scripts\restart_server_clear_log.ps1

# Check logs for specific error
Get-Content logs\server.log | Select-String "Vault|ERROR"
```

**Problem: "Permission denied" when signing certificates**
```powershell
# The Vault policy needs updating
# See "Vault Setup (One-Time)" section for policy creation

# Quick fix - verify policy exists:
$env:VAULT_ADDR = "http://127.0.0.1:8200"
& "C:\Program Files\HashiCorp\Vault\vault.exe" policy read pki-app

# If missing, recreate it (see Vault Integration section)
```

**Problem: Web UI shows "CA (RSA)" but config.ini has "mode = EC"**
```powershell
# Browser is caching old page
# Solution: Hard refresh in browser (Ctrl+Shift+R or Ctrl+F5)

# Or verify with curl:
curl.exe https://localhost/about -k | Select-String "CA \("

# Check server actually loaded EC mode:
Get-Content logs\server.log | Select-String "CA_MODE"
```

### Server Won't Stop
If the restart scripts can't stop the server:
```powershell
# Use the stop script
.\scripts\stop_server.ps1

# Or force kill all Python processes (nuclear option)
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force

# Or manually find and kill the process
Get-Process python | Select-Object Id, ProcessName, Path
Stop-Process -Id <process_id> -Force
```

### Port Already in Use
If you see "Address already in use" errors:
```powershell
# Check what's using the port
netstat -ano | findstr :8090
netstat -ano | findstr :443
netstat -ano | findstr :80

# Kill the process using the port
Stop-Process -Id <PID> -Force
```

### OpenSSL Not Found
If OpenSSL commands fail:
```powershell
# Check if OpenSSL is in PATH
$env:PATH

# Add OpenSSL manually
$env:PATH = "C:\Program Files\OpenSSL-Win64\bin;" + $env:PATH

# Test OpenSSL
openssl version
```

### Virtual Environment Issues
If Python can't find modules:
```powershell
# Activate virtual environment manually
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Then run the server
python app.py
```

### Log File Not Found
If log clearing fails:
```powershell
# Create logs directory
New-Item -ItemType Directory -Path logs -Force

# Check config.ini for log_file setting
Get-Content config.ini | Select-String "log_file"
```

## File Locations

```
PKI/
├── scripts/               # This directory
│   ├── README.md         # This file
│   ├── stop_server.ps1   # Stop server
│   ├── run_server.ps1    # Start server (foreground)
│   ├── restart_server.ps1 # Restart (keep logs)
│   ├── restart_server_clear_log.ps1 # Restart (clear logs)
│   └── migrate_db.ps1    # Database migration
├── app.py                # Flask application
├── config.ini            # Server configuration
├── migrate_db.py         # Database migration script
├── logs/                 # Server logs
│   └── server.log        # Main log file
└── db/                   # Database files
    └── certs.db          # SQLite database
```

## Best Practices

1. **Always use `restart_server_clear_log.ps1` for testing** - Ensures clean log files for debugging
2. **Run `migrate_db.ps1` after schema changes** - Keeps database in sync with code
3. **Check logs after starting server** - `Get-Content logs\server.log -Tail 20`
4. **Stop server before migration** - Prevents database lock issues
5. **Run scripts from project root** - All paths are relative to PKI directory

## Summary

**Script Overview:**

| Script | Purpose | Vault Support | Keep? |
|--------|---------|---------------|-------|
| `stop_server.ps1` | Stop server gracefully | N/A | ✅ Yes - for cleanup |
| `run_server.ps1` | Start server in foreground | ❌ No | ✅ Yes - for debugging |
| `restart_server.ps1` | Quick restart, keep logs | ✅ Yes | ✅ Yes - for development |
| `restart_server_clear_log.ps1` | Restart with clean logs | ✅ Yes | ✅ Yes - **most used** |
| `migrate_db.ps1` | Database schema updates | N/A | ✅ Yes - for maintenance |

**Vault Mode:**
- Both restart scripts (`restart_server.ps1` and `restart_server_clear_log.ps1`) automatically configure Vault credentials
- No manual environment variable setup needed
- Server automatically falls back to legacy mode if Vault connection fails

**Recommendation:** 
- Use `restart_server_clear_log.ps1` for **most scenarios** (testing, development, Vault mode)
- Use `stop_server.ps1` for **cleanup** before manual operations
- Use `run_server.ps1` for **debugging** with live output (no Vault auto-config)
- Keep all scripts - each serves a specific purpose

**CA Modes:**
- **RSA mode**: Uses `pki-subca-rsa` Vault engine (or `rad_ca_sub_rsa.key` in legacy)
- **EC mode**: Uses `pki-subca-ec` Vault engine (or `rad_ca_sub_ec.key` in legacy)
- Switch by editing `config.ini` [CA] mode and restarting server
