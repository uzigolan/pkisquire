# Install & Run

## Requirements
- Python 3.x
- PowerShell (for helper scripts on Windows)

## Setup (Windows)
1. From the repo root, create and activate a virtual environment:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
2. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
3. Initialize or migrate the database (idempotent):
   ```powershell
   python migrate_db.py
   ```

## Run the Server
From the repo root:
```powershell
python app.py
```

Logs are written under `logs/`.

## Stop the Server
From the repo root:
```powershell
.\scripts\stop_server.ps1
```

## Optional: Vault Mode
To run with HashiCorp Vault key isolation, enable it in `config.ini` and follow:
- `scripts/README.md`
- `scripts/VAULT_SCRIPTS_README.md`

