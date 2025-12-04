# Server Management Scripts

This directory contains PowerShell scripts for managing the PKI Flask server and database.

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
3. Starts Flask server in background (no new window)
4. Displays server endpoints (SCEP on 8090, Web UI on 5000)

**When to use:**
- Quick server restart after code changes
- Keeping existing logs for debugging
- Running server in background

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
5. Starts Flask server in background
6. Displays server endpoints

**When to use:** ⭐ **Use this for most scenarios**
- Testing after configuration changes
- Starting fresh debugging session
- Before running test suites
- Removing old log entries

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
# 1. Restart server with clean logs
.\scripts\restart_server_clear_log.ps1

# 2. Run tests
.\tests\scripts\test_sscep.ps1
.\tests\scripts\test_estclient_curl.ps1
.\tests\scripts\test_ocsp.ps1

# 3. Check logs for any issues
Get-Content logs\server.log -Tail 50
```

### Development Workflow
```powershell
# 1. Make code changes
# ... edit app.py, models.py, etc. ...

# 2. Restart server to apply changes
.\scripts\restart_server.ps1

# 3. Test your changes
# ... use web UI or API ...

# 4. If issues, restart with clean log
.\scripts\restart_server_clear_log.ps1
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

**Do you need `run_server.ps1`?**

**Yes**, all five scripts serve different purposes:

| Script | Purpose | Keep? |
|--------|---------|-------|
| `stop_server.ps1` | Stop server gracefully | ✅ Yes - for cleanup |
| `run_server.ps1` | Start server in foreground | ✅ Yes - for debugging |
| `restart_server.ps1` | Quick restart, keep logs | ✅ Yes - for development |
| `restart_server_clear_log.ps1` | Restart with clean logs | ✅ Yes - **most used** |
| `migrate_db.ps1` | Database schema updates | ✅ Yes - for maintenance |

**Recommendation:** Keep all scripts. Use `restart_server_clear_log.ps1` for most scenarios, `stop_server.ps1` for cleanup, and `run_server.ps1` for debugging with live output.
