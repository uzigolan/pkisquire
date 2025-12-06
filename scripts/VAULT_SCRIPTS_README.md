# Vault Management Scripts

This directory contains PowerShell scripts for managing HashiCorp Vault integration with Pikachu CA.

## Quick Start

### 1. Install Vault
```powershell
.\install_vault.ps1
```
Downloads and installs Vault to `C:\Program Files\HashiCorp\Vault`, adds to PATH.

### 2. Start Vault (Development Mode)
```powershell
.\start_vault.ps1 -Mode dev
```
Starts Vault in development mode - **insecure, for testing only**. Displays root token on startup.

### 3. Initialize PKI Engines
```powershell
.\init_vault_pki.ps1 -RootToken <root-token>
```
Sets up:
- PKI engines (`pki-subca-rsa`, `pki-subca-ec`)
- Transit engine for OCSP signing
- AppRole authentication
- PKI roles (scep-enrollment, est-enrollment, server-cert)

Displays **Role ID** and **Secret ID** - save these!

### 4. Set Environment Variables
```powershell
$env:VAULT_ROLE_ID = "<role-id>"
$env:VAULT_SECRET_ID = "<secret-id>"
```

### 5. Migrate CA Keys to Vault
```powershell
.\migrate_keys_to_vault.ps1
```
Securely transfers existing CA private keys from filesystem to Vault PKI engine.

Use `-DryRun` to test without making changes:
```powershell
.\migrate_keys_to_vault.ps1 -DryRun
```

### 6. Enable Vault in Pikachu CA
Edit `config.ini`:
```ini
[VAULT]
enabled = true
```

Restart server:
```powershell
.\restart_server.ps1
```

### 7. Verify Configuration
```powershell
.\check_vault_health.ps1
```
Comprehensive health check showing Vault status, PKI engines, authentication, and environment variables.

## Scripts Reference

### install_vault.ps1
Installs HashiCorp Vault on Windows.

**Parameters:**
- `-Version` - Vault version to install (default: 1.15.4)
- `-InstallPath` - Installation directory (default: C:\Program Files\HashiCorp\Vault)

**Example:**
```powershell
.\install_vault.ps1 -Version 1.16.0
```

### start_vault.ps1
Starts Vault server in dev or production mode.

**Parameters:**
- `-Mode` - Server mode: "dev" or "production" (default: dev)
- `-Address` - Listen address (default: 127.0.0.1:8200)
- `-ConfigFile` - Config file for production mode

**Examples:**
```powershell
# Development mode (in-memory, auto-unsealed)
.\start_vault.ps1 -Mode dev

# Production mode (persistent storage, requires unsealing)
.\start_vault.ps1 -Mode production
```

**Note:** This script blocks while Vault runs. Press Ctrl+C or use `stop_vault.ps1` to stop.

### stop_vault.ps1
Gracefully stops running Vault server.

**Example:**
```powershell
.\stop_vault.ps1
```

### init_vault_pki.ps1
Initializes Vault PKI engines and authentication for Pikachu CA.

**Parameters:**
- `-RootToken` - Vault root token (required)
- `-VaultAddr` - Vault address (default: http://127.0.0.1:8200)

**Example:**
```powershell
.\init_vault_pki.ps1 -RootToken hvs.abc123xyz
```

**Creates:**
- PKI engines: `pki-subca-rsa`, `pki-subca-ec`
- Transit engine: `transit`
- AppRole: `pikachu-ca` with policy
- Roles: `scep-enrollment`, `est-enrollment`, `server-cert`

**Outputs:** Role ID and Secret ID for AppRole authentication.

### migrate_keys_to_vault.ps1
Migrates existing CA private keys from filesystem to Vault.

**Parameters:**
- `-VaultAddr` - Vault address (default: http://127.0.0.1:8200)
- `-ConfigPath` - Path to config.ini (default: config.ini)
- `-DryRun` - Test without making changes

**Prerequisites:**
- Environment variables `VAULT_ROLE_ID` and `VAULT_SECRET_ID` must be set
- Run `init_vault_pki.ps1` first

**Examples:**
```powershell
# Dry run (test without changes)
.\migrate_keys_to_vault.ps1 -DryRun

# Actual migration
.\migrate_keys_to_vault.ps1
```

**Security:** Original keys remain on filesystem as backup. Move to secure storage after verification.

### check_vault_health.ps1
Comprehensive health check for Vault configuration.

**Parameters:**
- `-VaultAddr` - Vault address (default: http://127.0.0.1:8200)

**Example:**
```powershell
.\check_vault_health.ps1
```

**Checks:**
- Vault process status
- Server sealed/unsealed status
- Token validity
- PKI engines (pki-subca-rsa, pki-subca-ec, transit)
- AppRole authentication
- Environment variables (VAULT_ADDR, VAULT_TOKEN, VAULT_ROLE_ID, VAULT_SECRET_ID)

## Production Deployment

### Initial Setup
1. **Install Vault:**
   ```powershell
   .\install_vault.ps1
   ```

2. **Start in production mode:**
   ```powershell
   .\start_vault.ps1 -Mode production
   ```

3. **Initialize Vault (in another terminal):**
   ```powershell
   vault operator init
   ```
   Save the 5 unseal keys and root token securely!

4. **Unseal Vault (requires 3 of 5 keys):**
   ```powershell
   vault operator unseal <key1>
   vault operator unseal <key2>
   vault operator unseal <key3>
   ```

5. **Login with root token:**
   ```powershell
   $env:VAULT_TOKEN = "<root-token>"
   ```

6. **Initialize PKI engines:**
   ```powershell
   .\init_vault_pki.ps1 -RootToken $env:VAULT_TOKEN
   ```

7. **Set AppRole credentials:**
   ```powershell
   $env:VAULT_ROLE_ID = "<role-id-from-init>"
   $env:VAULT_SECRET_ID = "<secret-id-from-init>"
   ```

8. **Migrate CA keys:**
   ```powershell
   .\migrate_keys_to_vault.ps1
   ```

9. **Enable Vault in config.ini:**
   ```ini
   [VAULT]
   enabled = true
   ```

10. **Restart Pikachu CA:**
    ```powershell
    .\restart_server.ps1
    ```

### After Reboot
Production Vault requires unsealing after restart:
```powershell
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>
```

## Troubleshooting

### Vault won't start
- Check if already running: `Get-Process vault`
- Stop existing: `.\stop_vault.ps1`
- Check logs in Vault data directory

### "Cannot connect to Vault"
- Verify Vault is running: `Get-Process vault`
- Check address: `$env:VAULT_ADDR`
- Test connection: `vault status`

### "Vault is sealed"
Unseal with 3 of 5 keys:
```powershell
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>
```

### "Permission denied"
- Check token: `vault token lookup`
- Verify Role ID/Secret ID are set
- Check policy: `vault policy read pikachu-ca`

### Migration fails
- Ensure Vault is unsealed
- Verify credentials: `$env:VAULT_ROLE_ID`, `$env:VAULT_SECRET_ID`
- Check key file paths in config.ini
- Run with `-DryRun` first

### Health check shows issues
Run health check for detailed diagnostics:
```powershell
.\check_vault_health.ps1
```

Follow suggestions in output.

## Environment Variables

Set these for Pikachu CA to use Vault:

```powershell
# Vault server address
$env:VAULT_ADDR = "http://127.0.0.1:8200"

# AppRole credentials (from init_vault_pki.ps1)
$env:VAULT_ROLE_ID = "<your-role-id>"
$env:VAULT_SECRET_ID = "<your-secret-id>"

# Optional: For manual vault CLI commands
$env:VAULT_TOKEN = "<root-or-user-token>"
```

Make permanent (User level):
```powershell
[Environment]::SetEnvironmentVariable("VAULT_ADDR", "http://127.0.0.1:8200", "User")
[Environment]::SetEnvironmentVariable("VAULT_ROLE_ID", "<role-id>", "User")
[Environment]::SetEnvironmentVariable("VAULT_SECRET_ID", "<secret-id>", "User")
```

## Security Best Practices

1. **Never commit credentials** - Use environment variables only
2. **Keep unseal keys secure** - Store in separate secure locations
3. **Rotate Secret IDs** - Regenerate periodically
4. **Enable TLS in production** - Update start_vault.ps1 config
5. **Backup Vault data** - `C:\Program Files\HashiCorp\Vault\data`
6. **Use proper file permissions** - Restrict access to Vault directory
7. **Monitor Vault logs** - Check for unauthorized access attempts
8. **Keep filesystem keys as backup** - Until fully verified

## References

- [Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [PKI Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/pki)
- [AppRole Auth Method](https://developer.hashicorp.com/vault/docs/auth/approle)
- [Transit Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
