# Install & Run

## Requirements
- Python 3.x
- PowerShell (for helper scripts on Windows)

## Step 1: Create Virtual Environment (Windows)
From the repo root, create and activate a virtual environment:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## Step 2: Install Dependencies
```powershell
pip install -r requirements.txt
```

## Step 3: Configure PKI Inputs
- Edit `config.ini` and set `[CA]` output paths.
- Edit `ca_pki.ini` and set subject/extension values.

## Step 4: Generate Initial CA Keys/Certificates (First Run)
```powershell
python gen_ca_pki.py --config config.ini --pki-config ca_pki.ini
```

Use `--force` to overwrite existing CA outputs:
```powershell
python gen_ca_pki.py --config config.ini --pki-config ca_pki.ini --force
```

## Step 5: Initialize or Migrate Database (Idempotent)
```powershell
python migrate_db.py
```

## Step 6: Run the Server
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

## Optional: Linux/macOS Equivalent Commands
From the repo root:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python gen_ca_pki.py --config config.ini --pki-config ca_pki.ini
python migrate_db.py
python app.py
```

## Optional: Vault Mode
To run with HashiCorp Vault key isolation, enable it in `config.ini` and follow:
- `scripts/README.md`
- `scripts/VAULT_SCRIPTS_README.md`
