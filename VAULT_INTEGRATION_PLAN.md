# Software Key Vault Integration Plan
## HashiCorp Vault PKI Engine Integration for pkisquire CA

---

## ðŸ“‹ Executive Summary

**Objective**: Integrate HashiCorp Vault (or similar software key vault) to provide hardware-like isolation for CA private keys and Post-Quantum Cryptography (PQC) keys, protecting them from the main application server's process memory and file system.

**Security Benefit**: Implements defense-in-depth by isolating cryptographic operations from the application layer, mimicking HSM security principles using software-based secret sharing (Shamir's Secret Sharing) and strict access policies.

---

## ðŸŽ¯ Goals

1. **Key Isolation**: Remove CA private keys from filesystem and application memory
2. **Secure Signing Operations**: Perform all signing operations within Vault's secure boundary
3. **Granular Access Control**: Implement role-based access for different CA operations
4. **Audit Trail**: Leverage Vault's audit logging for all key operations
5. **PQC Support**: Ensure compatibility with Post-Quantum algorithms (Dilithium/ML-DSA)
6. **Zero Trust**: Application never has direct access to private key material

---

## ðŸ—ï¸ Current Architecture Analysis

### Current Key Management
```
File System (Plain or Encrypted PEM files)
    â”œâ”€â”€ pki-subca/rad_ca_sub_rsa.key  (RSA private key)
    â”œâ”€â”€ pki-subca/rad_ca_sub_ec.key   (ECC private key)
    â””â”€â”€ pki-root/rad_ca_root.key      (Root CA key)
```

### Current Signing Flow
```
1. Load private key from filesystem (ca.py:15)
   â””â”€â”€ CertificateAuthority.__init__() loads key into memory

2. Sign operations:
   a) Certificate signing (ca.py:62)
      â””â”€â”€ builder.sign(self.private_key, hash_alg(), backend)
   
   b) CSR signing via OpenSSL subprocess (app.py:2476, scep.py:186)
      â””â”€â”€ openssl x509 -req -CAkey <key_path>
   
   c) CRL signing (app.py:2060)
      â””â”€â”€ builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
   
   d) OCSP signing (app.py:2206, 2319, 2380)
      â””â”€â”€ builder.sign(private_key, hashes.SHA256())
```

### Key Components Requiring Modification

| Component | File | Current Behavior | Required Change |
|-----------|------|------------------|-----------------|
| CA Class | `ca.py` | Loads key from file | Load cert only, sign via Vault |
| SCEP Handler | `scep.py` | Uses CA.private_key | Replace with Vault signing |
| EST Handler | `app.py:2450+` | OpenSSL subprocess with -CAkey | Vault transit or PKI engine |
| CRL Generation | `app.py:2060` | Direct key signing | Vault CRL generation |
| OCSP Responder | `app.py:2206+` | Direct key signing | Vault OCSP signing |
| Key Generation | `x509_keys.py` | Local OpenSSL | Optional: Vault key generation |

---

## ðŸ” Target Architecture

### Vault PKI Engine Structure (When enabled=true)
```
Vault
â”œâ”€â”€ PKI Engine: pki-root/
â”‚   â”œâ”€â”€ Root CA Certificate
â”‚   â”œâ”€â”€ Root CA Private Key (sealed)
â”‚   â””â”€â”€ Roles: root-issuer
â”‚
â”œâ”€â”€ PKI Engine: pki-subca-rsa/
â”‚   â”œâ”€â”€ Intermediate Certificate (RSA)
â”‚   â”œâ”€â”€ Intermediate Private Key (sealed)
â”‚   â””â”€â”€ Roles: 
â”‚       â”œâ”€â”€ server-cert
â”‚       â”œâ”€â”€ client-cert
â”‚       â””â”€â”€ scep-enrollment
â”‚
â”œâ”€â”€ PKI Engine: pki-subca-ec/
â”‚   â”œâ”€â”€ Intermediate Certificate (ECC)
â”‚   â”œâ”€â”€ Intermediate Private Key (sealed)
â”‚   â””â”€â”€ Roles: (similar to RSA)
â”‚
â””â”€â”€ Transit Engine: pqc-signing/
    â”œâ”€â”€ PQC Keys (Dilithium/ML-DSA)
    â””â”€â”€ Custom signing operations
```

### Configuration-Based Architecture

The system supports **two operational modes** controlled by `config.ini`:

#### Mode 1: Legacy File-Based Keys (enabled=false)
```
Application
    â†“
Load keys from filesystem
    â†“
Sign operations in-process
    â†“
Private keys in memory
```

**Configuration:**
```ini
[VAULT]
enabled = false

[CA]
SUBCA_KEY_PATH_RSA = pki-subca/rad_ca_sub_rsa.key
SUBCA_KEY_PATH_EC = pki-subca/rad_ca_sub_ec.key
```

#### Mode 2: Vault-Isolated Keys (enabled=true)
```
Application
    â†“
Vault API calls
    â†“
Sign operations in Vault
    â†“
Keys never leave Vault
```

**Configuration:**
```ini
[VAULT]
enabled = true
address = https://vault.example.com:8200

[CA]
# Key paths not required when Vault is enabled
# Only certificate/chain paths are needed
```

### New Signing Flow
```
1. Application requests signing from Vault
   â””â”€â”€ No private key in app memory

2. Sign operations via Vault API:
   a) Certificate signing
      â””â”€â”€ POST /v1/pki-subca-rsa/sign/<role>
   
   b) CSR signing
      â””â”€â”€ POST /v1/pki-subca-rsa/sign/<role>
   
   c) CRL generation
      â””â”€â”€ GET /v1/pki-subca-rsa/crl/pem
   
   d) OCSP signing
      â””â”€â”€ POST /v1/transit/pqc-signing/sign/<key>
   
   e) Raw signature (for SCEP/EST)
      â””â”€â”€ POST /v1/transit/sign/<key>
```

---

## ðŸ› ï¸ Implementation Plan

### Phase 1: Infrastructure Setup (Week 1)

#### 1.0 Vault Deployment Architecture Decision

**Vault can be deployed in several ways:**

##### Option 1: Separate Dedicated Server (RECOMMENDED for Production)
```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”         â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚   PKI Application   â”‚  API    â”‚   Vault Server      â”‚
â”‚   (Rocky Linux 9)   â”‚ â—„â”€â”€â”€â”€â”€â–º â”‚   (Linux/Any OS)    â”‚
â”‚   Port 5000, 8090   â”‚  HTTPS  â”‚   Port 8200         â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜         â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

**Pros:**
- âœ… **Best security** - Physical/network isolation from application
- âœ… **Independent scaling** - Vault can serve multiple applications
- âœ… **Easier to harden** - Dedicated security policies
- âœ… **High availability** - Can use Vault cluster (3-5 nodes)
- âœ… **OS independence** - Vault runs on Linux, Windows, macOS, Docker

**Cons:**
- âš ï¸ Network latency (~5-15ms additional per operation)
- âš ï¸ Requires separate infrastructure
- âš ï¸ More complex deployment

**Best for:** Production environments, multiple CA instances, high-security requirements

---

##### Option 2: Same Server (Acceptable for Dev/Testing)
```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚      Same Linux Server          â”‚
â”‚                                 â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”           â”‚
â”‚  â”‚ PKI Application  â”‚           â”‚
â”‚  â”‚ localhost:5000   â”‚           â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜           â”‚
â”‚           â†“ localhost           â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”           â”‚
â”‚  â”‚ Vault Server     â”‚           â”‚
â”‚  â”‚ localhost:8200   â”‚           â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜           â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

**Pros:**
- âœ… **Simple setup** - Single server to manage
- âœ… **No network latency** - Unix socket or localhost communication
- âœ… **Lower infrastructure cost**
- âœ… **Easy for development/testing**

**Cons:**
- âŒ **Shared security boundary** - Compromise of app server = access to Vault
- âŒ **Single point of failure** - Server down = both services down
- âŒ **Resource contention** - App and Vault compete for CPU/memory
- âŒ **Limited isolation benefit** - Reduces security advantage

**Best for:** Development, testing, small deployments, proof-of-concept

---

##### Option 3: Containerized Vault (Modern Approach)
```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚         Docker Host / Kubernetes        â”‚
â”‚                                         â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
â”‚  â”‚ PKI App     â”‚   â”‚ Vault          â”‚  â”‚
â”‚  â”‚ Container   â”‚â”€â”€â”€â”‚ Container      â”‚  â”‚
â”‚  â”‚             â”‚   â”‚ (Isolated)     â”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

**Pros:**
- âœ… **Container isolation** - Better than same-process
- âœ… **Easy deployment** - Docker Compose or Kubernetes
- âœ… **Portable** - Runs anywhere with container runtime
- âœ… **Resource limits** - CPU/memory controls

**Best for:** Cloud deployments, Kubernetes environments, microservices

---

#### Recommendation by Use Case

| Use Case | Recommended Setup | Rationale |
|----------|-------------------|-----------|
| **Production CA** | Separate Vault cluster (3-5 nodes) | Maximum security & availability |
| **Enterprise PKI** | Separate Vault in DMZ | Network segmentation |
| **Development** | Same server, separate process | Simplicity |
| **Testing** | Docker Compose (2 containers) | Easy teardown/rebuild |
| **Cloud Deployment** | Managed Vault (HCP Vault) | Fully managed, auto-unsealed |

---

#### ðŸŽ¯ Chosen Architecture for This Implementation

**Separate Vault Application - Portable Design**

```
Current Setup (Phase 1):
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚     Same Rocky Linux 9 Server           â”‚
â”‚                                          â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”     â”‚
â”‚  â”‚ pkisquire CA Application         â”‚     â”‚
â”‚  â”‚ - Flask on port 5000           â”‚     â”‚
â”‚  â”‚ - SCEP on port 8090            â”‚     â”‚
â”‚  â”‚ - User: pki_app                â”‚     â”‚
â”‚  â”‚ - Config: /opt/pkisquire-ca      â”‚     â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜     â”‚
â”‚              â†“ Network API               â”‚
â”‚              (127.0.0.1:8200)            â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”     â”‚
â”‚  â”‚ HashiCorp Vault (Standalone)   â”‚     â”‚
â”‚  â”‚ - Vault on port 8200           â”‚     â”‚
â”‚  â”‚ - User: vault                  â”‚     â”‚
â”‚  â”‚ - Config: /etc/vault.d         â”‚     â”‚
â”‚  â”‚ - Data: /opt/vault/data        â”‚     â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜     â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Future Setup (Phase 2 - Simple Migration):
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”         â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Rocky Linux 9       â”‚         â”‚ Rocky Linux 9       â”‚
â”‚ PKI App Server      â”‚  API    â”‚ Vault Server        â”‚
â”‚                     â”‚ â—„â”€â”€â”€â”€â”€â–º â”‚                     â”‚
â”‚ pkisquire CA          â”‚  8200   â”‚ HashiCorp Vault     â”‚
â”‚ (192.168.1.10)      â”‚  HTTPS  â”‚ (192.168.1.20)      â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜         â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

**Migration: Just change config.ini address from 127.0.0.1 to 192.168.1.20**

```ini
# Before migration (same server):
[VAULT]
enabled = true
address = https://127.0.0.1:8200

# After migration (separate server):
[VAULT]
enabled = true
address = https://192.168.1.20:8200

# That's it! Restart the PKI app and it connects to the new Vault server.
```

**Design Principles:**
- âœ… **Completely separate applications** - Different users, configs, data directories
- âœ… **Network-based communication** - No shared files or memory
- âœ… **Zero-dependency installation** - Each can be installed/removed independently
- âœ… **Location transparent** - Works on localhost or remote server
- âœ… **Easy migration** - Change IP address in config, no code changes
- âœ… **Service isolation** - Separate systemd services, independent restarts

---

#### 1.1 Vault Installation & Configuration

**Standalone Vault Installation (Portable Design)**

This setup installs Vault as a completely independent application that can run on the same machine initially and be migrated to a separate machine later with just a configuration change.

---

**Step 1: Install Vault as Separate Application**

```bash
# On Rocky Linux 9 (can be same server or different server)

# Add HashiCorp repository
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo

# Install Vault
sudo yum install vault -y

# Verify installation
vault version
# Expected output: Vault v1.15.x
```

---

**Step 2: Create Dedicated Vault User & Directory Structure**

```bash
# Create dedicated vault user (separate from PKI app)
sudo useradd --system --home /etc/vault.d --shell /bin/false vault

# Create directory structure
sudo mkdir -p /opt/vault/data
sudo mkdir -p /etc/vault.d
sudo mkdir -p /var/log/vault

# Set ownership
sudo chown -R vault:vault /opt/vault
sudo chown -R vault:vault /etc/vault.d
sudo chown -R vault:vault /var/log/vault

# Set permissions (restrictive)
sudo chmod 700 /opt/vault/data
sudo chmod 750 /etc/vault.d
```

---

**Step 3: Configure Vault (Network-Ready)**

```bash
# Create Vault configuration file
sudo tee /etc/vault.d/vault.hcl <<'EOF'
# Vault Configuration for pkisquire CA Integration
# This config works for both same-server and separate-server deployment

# Storage backend - file-based (change to Consul/etcd for HA)
storage "file" {
  path = "/opt/vault/data"
}

# Network listener - binds to all interfaces for portability
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = 0
  tls_cert_file = "/etc/vault.d/vault-cert.pem"
  tls_key_file  = "/etc/vault.d/vault-key.pem"
  
  # Optional: Client certificate validation
  # tls_require_and_verify_client_cert = true
  # tls_client_ca_file = "/etc/vault.d/ca-cert.pem"
}

# API address - update this when moving to separate server
api_addr = "https://127.0.0.1:8200"  # Change to public IP when separating

# Cluster address (for future HA setup)
cluster_addr = "https://127.0.0.1:8201"

# Enable UI (optional)
ui = true

# Logging
log_level = "info"
log_file  = "/var/log/vault/vault.log"

# Telemetry (optional)
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}
EOF

sudo chown vault:vault /etc/vault.d/vault.hcl
sudo chmod 640 /etc/vault.d/vault.hcl
```

---

**Step 4: Generate TLS Certificates for Vault**

```bash
# Option A: Use your CA to generate Vault server certificate
cd /etc/vault.d

# Generate private key
sudo openssl genrsa -out vault-key.pem 4096

# Generate CSR
sudo openssl req -new -key vault-key.pem -out vault.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=vault.local"

# Create extensions file for SAN
sudo tee vault-ext.cnf <<EOF
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = vault.local
IP.1 = 127.0.0.1
IP.2 = 192.168.1.20
# Add your server's IP addresses
EOF

# Sign with your CA (or use self-signed for testing)
# Using pkisquire CA:
# sudo openssl x509 -req -in vault.csr \
#   -CA /path/to/ca.crt -CAkey /path/to/ca.key \
#   -out vault-cert.pem -days 3650 \
#   -extfile vault-ext.cnf

# OR self-signed for testing:
sudo openssl x509 -req -in vault.csr -signkey vault-key.pem \
  -out vault-cert.pem -days 3650 -extfile vault-ext.cnf

# Set permissions
sudo chown vault:vault vault-key.pem vault-cert.pem
sudo chmod 400 vault-key.pem
sudo chmod 444 vault-cert.pem
```

---

**Step 5: Create Systemd Service (Independent from PKI App)**

```bash
# Create vault systemd service
sudo tee /etc/systemd/system/vault.service <<'EOF'
[Unit]
Description=HashiCorp Vault - Secure Key Management
Documentation=https://www.vaultproject.io/docs/
After=network-online.target
Wants=network-online.target
ConditionFileNotEmpty=/etc/vault.d/vault.hcl

[Service]
Type=notify
User=vault
Group=vault
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=/usr/bin/vault server -config=/etc/vault.d/vault.hcl
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

# Enable vault service
sudo systemctl enable vault

# Start vault service
sudo systemctl start vault

# Check status
sudo systemctl status vault
```

---

**Step 6: Initialize and Unseal Vault (First Time Only)**

```bash
# Set Vault address
export VAULT_ADDR='https://127.0.0.1:8200'
export VAULT_SKIP_VERIFY=1  # Only if using self-signed cert

# Initialize Vault (produces unseal keys and root token)
vault operator init -key-shares=5 -key-threshold=3

# CRITICAL: Save the output securely!
# Example output:
# Unseal Key 1: xxx...
# Unseal Key 2: xxx...
# Unseal Key 3: xxx...
# Unseal Key 4: xxx...
# Unseal Key 5: xxx...
# Initial Root Token: hvs.xxx...

# Unseal Vault (requires 3 of 5 keys)
vault operator unseal <unseal-key-1>
vault operator unseal <unseal-key-2>
vault operator unseal <unseal-key-3>

# Verify Vault is unsealed
vault status
# Should show: Sealed: false

# Login with root token
vault login <root-token>
```

---

**Step 7: Configure Firewall (Allows Remote Access)**

```bash
# Allow Vault port (for future separate-server deployment)
sudo firewall-cmd --permanent --add-port=8200/tcp
sudo firewall-cmd --permanent --add-port=8201/tcp  # For clustering
sudo firewall-cmd --reload

# For same-server setup, optionally restrict to localhost:
# sudo firewall-cmd --permanent --add-rich-rule='
#   rule family="ipv4" source address="127.0.0.1" 
#   port port="8200" protocol="tcp" accept'
```

---

**Step 8: Verify Vault is Running Independently**

```bash
# Check Vault service status
sudo systemctl status vault

# Check Vault is listening
sudo ss -tlnp | grep 8200

# Test API endpoint
curl -k https://127.0.0.1:8200/v1/sys/health

# Expected output: {"initialized":true,"sealed":false,...}

# Verify separation from PKI app
ps aux | grep vault  # Shows vault process under 'vault' user
ps aux | grep python # Shows PKI app under different user
```

---

**Step 9: Create Unseal Script (For Auto-Restart)**

```bash
# Create unseal helper script
sudo tee /usr/local/bin/vault-unseal.sh <<'EOF'
#!/bin/bash
# Vault Auto-Unseal Script
# Store unseal keys in a secure location (e.g., encrypted file, KMS)

export VAULT_ADDR='https://127.0.0.1:8200'
export VAULT_SKIP_VERIFY=1

# Load unseal keys from secure storage
# NEVER hardcode keys in production!
KEY1=$(cat /root/.vault/unseal-key-1)  # Secure this!
KEY2=$(cat /root/.vault/unseal-key-2)
KEY3=$(cat /root/.vault/unseal-key-3)

vault operator unseal "$KEY1"
vault operator unseal "$KEY2"
vault operator unseal "$KEY3"

echo "Vault unsealed successfully"
EOF

sudo chmod 700 /usr/local/bin/vault-unseal.sh
sudo chown root:root /usr/local/bin/vault-unseal.sh
```

---

**Migration to Separate Server (Future):**

When you're ready to move Vault to a different machine:

```bash
# On new Vault server:
# 1. Install Vault (repeat Steps 1-5)
# 2. Stop PKI app's Vault service: sudo systemctl stop vault
# 3. Copy /opt/vault/data to new server (secure transfer!)
# 4. Update vault.hcl with new IP address
# 5. Start Vault on new server
# 6. Unseal Vault

# On PKI app server:
# 1. Edit /opt/pkisquire-ca/config.ini:
#    [VAULT]
#    address = https://192.168.1.20:8200  # New Vault server IP
# 2. Restart PKI app: ./scripts/restart_server.ps1
# 3. No code changes needed!
```

#### 1.2 Enable Required Engines
```bash
# Enable PKI engines
vault secrets enable -path=pki-root pki
vault secrets enable -path=pki-subca-rsa pki
vault secrets enable -path=pki-subca-ec pki

# Enable Transit engine for PQC and custom signing
vault secrets enable transit

# Configure PKI TTLs
vault secrets tune -max-lease-ttl=87600h pki-root
vault secrets tune -max-lease-ttl=43800h pki-subca-rsa
vault secrets tune -max-lease-ttl=43800h pki-subca-ec
```

#### 1.3 Migrate Existing Keys to Vault
```bash
# Import existing Root CA
vault write pki-root/config/ca \
    pem_bundle=@pki-root/rad_ca_root_bundle.pem

# Import RSA Sub-CA
vault write pki-subca-rsa/config/ca \
    pem_bundle=@pki-subca/rad_ca_sub_rsa_bundle.pem

# Import ECC Sub-CA
vault write pki-subca-ec/config/ca \
    pem_bundle=@pki-subca/rad_ca_sub_ec_bundle.pem
```

#### 1.4 Create Vault Policies
```hcl
# File: vault-policies/pkisquire-ca-app.hcl
path "pki-subca-rsa/sign/*" {
  capabilities = ["create", "update"]
}

path "pki-subca-ec/sign/*" {
  capabilities = ["create", "update"]
}

path "pki-subca-rsa/crl" {
  capabilities = ["read"]
}

path "transit/sign/pqc-*" {
  capabilities = ["update"]
}

path "transit/verify/pqc-*" {
  capabilities = ["update"]
}
```

```bash
vault policy write pkisquire-ca-app vault-policies/pkisquire-ca-app.hcl
```

#### 1.5 Setup Authentication
```bash
# Create AppRole for the application
vault auth enable approle

vault write auth/approle/role/pkisquire-ca \
    token_policies="pkisquire-ca-app" \
    token_ttl=1h \
    token_max_ttl=4h

# Get credentials
vault read auth/approle/role/pkisquire-ca/role-id
vault write -f auth/approle/role/pkisquire-ca/secret-id
```

---

### Phase 2: Code Refactoring (Week 2-3)

#### 2.1 Create Vault Client Module
**New File: `vault_client.py`**
```python
"""
HashiCorp Vault integration for CA operations.
Provides key isolation and secure signing operations.
"""
import hvac
import os
from typing import Optional, Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64


class VaultClient:
    """Wrapper for HashiCorp Vault PKI and Transit operations"""
    
    def __init__(self, vault_addr: str, role_id: str, secret_id: str):
        """Initialize Vault client with AppRole authentication"""
        self.client = hvac.Client(url=vault_addr)
        self.client.auth.approle.login(
            role_id=role_id,
            secret_id=secret_id
        )
    
    def sign_csr(self, 
                 csr: x509.CertificateSigningRequest,
                 pki_path: str,
                 role: str,
                 ttl: str = "8760h",
                 extensions: Optional[Dict[str, Any]] = None) -> x509.Certificate:
        """
        Sign a CSR using Vault PKI engine.
        
        Args:
            csr: Certificate Signing Request
            pki_path: Vault PKI mount path (e.g., "pki-subca-rsa")
            role: Vault role name
            ttl: Certificate validity period
            extensions: Additional x509 extensions
            
        Returns:
            Signed x509.Certificate object
        """
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        
        response = self.client.write(
            f"{pki_path}/sign/{role}",
            csr=csr_pem,
            ttl=ttl,
            format="pem"
        )
        
        cert_pem = response['data']['certificate']
        return x509.load_pem_x509_certificate(
            cert_pem.encode(),
            default_backend()
        )
    
    def get_ca_certificate(self, pki_path: str) -> x509.Certificate:
        """Retrieve CA certificate from Vault"""
        response = self.client.read(f"{pki_path}/cert/ca")
        cert_pem = response['data']['certificate']
        return x509.load_pem_x509_certificate(
            cert_pem.encode(),
            default_backend()
        )
    
    def get_crl(self, pki_path: str) -> bytes:
        """Retrieve CRL from Vault PKI engine"""
        response = self.client.read(f"{pki_path}/crl/pem")
        return response['data']['crl'].encode()
    
    def sign_data(self, 
                  transit_key: str,
                  data: bytes,
                  hash_algorithm: str = "sha2-256") -> bytes:
        """
        Sign arbitrary data using Transit engine.
        Used for OCSP responses and custom signatures.
        
        Args:
            transit_key: Transit key name
            data: Data to sign
            hash_algorithm: Hashing algorithm
            
        Returns:
            Raw signature bytes
        """
        # Base64 encode the data
        data_b64 = base64.b64encode(data).decode()
        
        response = self.client.write(
            f"transit/sign/{transit_key}",
            input=data_b64,
            hash_algorithm=hash_algorithm,
            signature_algorithm="pkcs1v15"
        )
        
        # Vault returns signature in format "vault:v1:base64sig"
        sig_parts = response['data']['signature'].split(':')
        sig_b64 = sig_parts[-1]
        return base64.b64decode(sig_b64)
    
    def rotate_key(self, transit_key: str):
        """Rotate a transit encryption key"""
        self.client.write(f"transit/keys/{transit_key}/rotate")
    
    def health_check(self) -> bool:
        """Check Vault connectivity and authentication"""
        try:
            return self.client.sys.is_initialized() and self.client.is_authenticated()
        except Exception:
            return False
```

#### 2.2 Refactor CA Class
**Modified: `ca.py`**
```python
# ca.py - Updated with optional Vault support

import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import Optional


class CertificateAuthority:
    """
    CA operations with optional Vault-backed key isolation.
    
    Supports two modes:
    1. Legacy mode: Load private key from file (current behavior)
    2. Vault mode: Keys isolated in Vault, signing via API
    """
    
    def __init__(self, 
                 key_path: Optional[str] = None,
                 chain_path: str = None,
                 vault_client = None,
                 pki_path: Optional[str] = None,
                 default_role: str = "server-cert"):
        """
        Initialize CA with either file-based or Vault-based keys.
        
        Args:
            key_path: Path to private key file (required if vault_client=None)
            chain_path: Path to CA certificate chain
            vault_client: VaultClient instance (optional, enables Vault mode)
            pki_path: Vault PKI mount path (required if vault_client is provided)
            default_role: Default Vault signing role
        """
        # Load CA certificate chain (always required)
        with open(chain_path, "rb") as f:
            pem_chain = f.read()
        first_pem = pem_chain.split(b"-----END CERTIFICATE-----")[0] + \
                    b"-----END CERTIFICATE-----\n"
        self._certificate = x509.load_pem_x509_certificate(
            first_pem, 
            default_backend()
        )
        
        # Determine operation mode
        self._vault_enabled = vault_client is not None
        
        if self._vault_enabled:
            # Vault mode: No private key in memory
            if not pki_path:
                raise ValueError("pki_path required when using Vault")
            self._vault = vault_client
            self._pki_path = pki_path
            self._default_role = default_role
            self._private_key = None
        else:
            # Legacy mode: Load private key from file
            if not key_path:
                raise ValueError("key_path required when not using Vault")
            with open(key_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(), 
                    password=None, 
                    backend=default_backend()
                )
            self._vault = None
    
    @property
    def certificate(self) -> x509.Certificate:
        """Public CA certificate"""
        return self._certificate
    
    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        """
        Access to private key.
        
        In Vault mode, this raises NotImplementedError.
        In legacy mode, returns the loaded private key.
        """
        if self._vault_enabled:
            raise NotImplementedError(
                "Direct private key access is not available with Vault integration. "
                "Use sign() method for signing operations."
            )
        return self._private_key
    
    def sign(self,
             csr: x509.CertificateSigningRequest,
             days: int = 365,
             hash_alg=hashes.SHA256,
             role: Optional[str] = None,
             extensions: Optional[dict] = None) -> x509.Certificate:
        """
        Sign a CSR using either Vault or local private key.
        
        Args:
            csr: Certificate Signing Request
            days: Validity period in days
            hash_alg: Hash algorithm (used in legacy mode)
            role: Vault role (Vault mode only)
            extensions: Additional extensions (Vault mode only)
            
        Returns:
            Signed certificate
        """
        if self._vault_enabled:
            # Vault mode: Sign via Vault PKI engine
            ttl = f"{days * 24}h"
            role = role or self._default_role
            
            return self._vault.sign_csr(
                csr=csr,
                pki_path=self._pki_path,
                role=role,
                ttl=ttl,
                extensions=extensions
            )
        else:
            # Legacy mode: Sign with local private key
            builder = (
                x509.CertificateBuilder()
                .subject_name(csr.subject)
                .issuer_name(self.certificate.subject)
                .public_key(csr.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            )
            return builder.sign(self.private_key, hash_alg(), default_backend())
    
    def sign_data(self, data: bytes) -> bytes:
        """
        Sign arbitrary data (for SCEP, OCSP, etc.)
        
        Args:
            data: Raw data to sign
            
        Returns:
            Signature bytes
        """
        if self._vault_enabled:
            transit_key = f"{self._pki_path}-signing"
            return self._vault.sign_data(transit_key, data)
        else:
            # Legacy mode: Use cryptography library for signing
            from cryptography.hazmat.primitives.asymmetric import padding
            return self.private_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
    
    def signer_identifier(self) -> bytes:
        """Build IssuerAndSerialNumber for SCEP (works in both modes)"""
        from asn1crypto import x509 as asn1_x509
        from asn1crypto.cms import SignerIdentifier, IssuerAndSerialNumber
        
        der = self.certificate.public_bytes(serialization.Encoding.DER)
        asn1cert = asn1_x509.Certificate.load(der)
        
        ias = IssuerAndSerialNumber({
            'issuer': asn1cert.issuer,
            'serial_number': asn1cert.serial_number
        })
        sid = SignerIdentifier('issuer_and_serial_number', ias)
        return sid.dump()
```

#### 2.3 Update Configuration
**Modified: `config.ini`**

All Vault-related settings are centralized in the `[VAULT]` section for easy management:

```ini
[VAULT]
# Enable/Disable Vault integration
# false = Use traditional file-based keys (current behavior)
# true = Use Vault PKI engine (enhanced security)
enabled = false

# Vault server connection (required when enabled=true)
address = https://127.0.0.1:8200
# For separate server, change to: https://192.168.1.20:8200

# Authentication credentials (read from environment variables for security)
role_id = ${VAULT_ROLE_ID}
secret_id = ${VAULT_SECRET_ID}

# PKI mount paths in Vault
pki_rsa_path = pki-subca-rsa
pki_ec_path = pki-subca-ec

# Transit engine path for custom signing operations (OCSP, PQC)
transit_path = transit

# Connection settings
timeout = 30
retry_attempts = 3

# TLS settings
verify_ssl = true
ca_cert_path = /etc/vault.d/vault-cert.pem
# Set verify_ssl=false only for testing with self-signed certs

# Vault roles for different operations
role_scep = scep-enrollment
role_est = est-enrollment
role_default = server-cert

[CA]
mode = RSA

# File-based key paths (used when VAULT.enabled=false)
SUBCA_KEY_PATH_EC    = pki-subca/rad_ca_sub_ec.key
SUBCA_KEY_PATH_RSA   = pki-subca/rad_ca_sub_rsa.key

# Certificate paths (always required, regardless of Vault setting)
SUBCA_CERT_PATH_EC   = pki-subca/rad_ca_sub_ec.crt
CHAIN_FILE_PATH_EC   = pki-subca/rad_chain_ec.crt
SUBCA_CERT_PATH_RSA  = pki-subca/rad_ca_sub_rsa.crt
CHAIN_FILE_PATH_RSA  = pki-subca/rad_chain_rsa.crt
ROOT_CERT_PATH       = pki-root/rad_ca_root.crt
```

**Configuration File Loading in Application:**

```python
# app.py or config_storage.py

import configparser
import os

def load_vault_config(config_path='config.ini'):
    """Load Vault configuration from config.ini"""
    config = configparser.ConfigParser()
    config.read(config_path)
    
    vault_config = {}
    
    if config.has_section('VAULT'):
        # Basic settings
        vault_config['enabled'] = config.getboolean('VAULT', 'enabled', fallback=False)
        vault_config['address'] = config.get('VAULT', 'address', fallback='https://127.0.0.1:8200')
        
        # Authentication - read from environment variables
        role_id_var = config.get('VAULT', 'role_id', fallback='${VAULT_ROLE_ID}')
        secret_id_var = config.get('VAULT', 'secret_id', fallback='${VAULT_SECRET_ID}')
        
        # Expand environment variables
        vault_config['role_id'] = os.environ.get('VAULT_ROLE_ID') if '${' in role_id_var else role_id_var
        vault_config['secret_id'] = os.environ.get('VAULT_SECRET_ID') if '${' in secret_id_var else secret_id_var
        
        # PKI paths
        vault_config['pki_rsa_path'] = config.get('VAULT', 'pki_rsa_path', fallback='pki-subca-rsa')
        vault_config['pki_ec_path'] = config.get('VAULT', 'pki_ec_path', fallback='pki-subca-ec')
        vault_config['transit_path'] = config.get('VAULT', 'transit_path', fallback='transit')
        
        # Connection settings
        vault_config['timeout'] = config.getint('VAULT', 'timeout', fallback=30)
        vault_config['retry_attempts'] = config.getint('VAULT', 'retry_attempts', fallback=3)
        
        # TLS settings
        vault_config['verify_ssl'] = config.getboolean('VAULT', 'verify_ssl', fallback=True)
        vault_config['ca_cert_path'] = config.get('VAULT', 'ca_cert_path', fallback=None)
        
        # Vault roles
        vault_config['role_scep'] = config.get('VAULT', 'role_scep', fallback='scep-enrollment')
        vault_config['role_est'] = config.get('VAULT', 'role_est', fallback='est-enrollment')
        vault_config['role_default'] = config.get('VAULT', 'role_default', fallback='server-cert')
    else:
        # No VAULT section = disabled by default
        vault_config['enabled'] = False
    
    return vault_config

# Usage in application
VAULT_CONFIG = load_vault_config()
```

**Environment Variable Setup:**

```bash
# For production, set environment variables (never hardcode credentials!)
export VAULT_ROLE_ID="your-role-id-here"
export VAULT_SECRET_ID="your-secret-id-here"

# Or add to systemd service file:
# /etc/systemd/system/pkisquire-ca.service
[Service]
Environment="VAULT_ROLE_ID=xxx"
Environment="VAULT_SECRET_ID=xxx"

# Or use a separate env file:
# /opt/pkisquire-ca/.env
VAULT_ROLE_ID=xxx
VAULT_SECRET_ID=xxx
```

#### 2.4 Update Application Initialization
**Modified: `app.py` (initialization section)**
```python
# app.py - Add optional Vault initialization

from vault_client import VaultClient
from config_storage import load_vault_config  # Centralized config loading

# Load Vault configuration from config.ini
VAULT_CONFIG = load_vault_config()

# Initialize Vault client (optional, based on config.ini)
def init_vault_client():
    """
    Initialize Vault client from config.ini [VAULT] section.
    Returns None if Vault is disabled, allowing fallback to file-based keys.
    """
    if not VAULT_CONFIG.get('enabled', False):
        app.logger.info("Vault integration is DISABLED (config.ini [VAULT] enabled=false)")
        app.logger.info("Using file-based keys from config.ini [CA] section")
        return None
    
    app.logger.info("Vault integration is ENABLED (config.ini [VAULT] enabled=true)")
    
    vault_addr = VAULT_CONFIG.get('address')
    if not vault_addr:
        raise RuntimeError("VAULT address must be set in config.ini when enabled=true")
    
    role_id = VAULT_CONFIG.get('role_id')
    secret_id = VAULT_CONFIG.get('secret_id')
    
    if not role_id or not secret_id:
        raise RuntimeError(
            "VAULT_ROLE_ID and VAULT_SECRET_ID must be set in environment "
            "or config.ini when VAULT enabled=true"
        )
    
    try:
        # Create Vault client with settings from config.ini
        vault = VaultClient(
            vault_addr=vault_addr,
            role_id=role_id,
            secret_id=secret_id,
            verify_ssl=VAULT_CONFIG.get('verify_ssl', True),
            ca_cert=VAULT_CONFIG.get('ca_cert_path'),
            timeout=VAULT_CONFIG.get('timeout', 30)
        )
        
        if not vault.health_check():
            raise RuntimeError(f"Vault health check failed for {vault_addr}")
        
        app.logger.info(f"âœ“ Vault client connected to {vault_addr}")
        return vault
    except Exception as e:
        app.logger.error(f"Failed to initialize Vault: {e}")
        raise

# Global Vault client (None if disabled in config.ini)
vault_client = None

@app.before_first_request
def setup_vault():
    """Initialize Vault if enabled in config.ini [VAULT] section"""
    global vault_client
    vault_client = init_vault_client()
    
    if vault_client:
        app.config['VAULT_CLIENT'] = vault_client
        app.config['VAULT_CONFIG'] = VAULT_CONFIG
        app.logger.info("Running in VAULT MODE - keys isolated in Vault")
        app.logger.info(f"  RSA PKI path: {VAULT_CONFIG['pki_rsa_path']}")
        app.logger.info(f"  EC PKI path: {VAULT_CONFIG['pki_ec_path']}")
    else:
        app.logger.info("Running in LEGACY MODE - using file-based keys")
        app.logger.info(f"  RSA key: {app.config['SUBCA_KEY_PATH_RSA']}")
        app.logger.info(f"  EC key: {app.config['SUBCA_KEY_PATH_EC']}")

# Helper function to create CA instance with correct mode (reads from config.ini)
def get_ca_instance():
    """
    Create CertificateAuthority instance based on config.ini settings.
    Automatically uses Vault or file-based keys depending on [VAULT] enabled setting.
    """
    ca_mode = app.config.get('CA_MODE', 'RSA')
    
    if ca_mode == 'EC':
        key_path = app.config.get('SUBCA_KEY_PATH_EC')
        chain_path = app.config['CHAIN_FILE_PATH_EC']
        pki_path = VAULT_CONFIG.get('pki_ec_path')
    else:
        key_path = app.config.get('SUBCA_KEY_PATH_RSA')
        chain_path = app.config['CHAIN_FILE_PATH_RSA']
        pki_path = VAULT_CONFIG.get('pki_rsa_path')
    
    if vault_client:
        # Vault mode (config.ini [VAULT] enabled=true)
        return CertificateAuthority(
            chain_path=chain_path,
            vault_client=vault_client,
            pki_path=pki_path,
            default_role=VAULT_CONFIG.get('role_default', 'server-cert')
        )
    else:
        # Legacy mode (config.ini [VAULT] enabled=false)
        return CertificateAuthority(
            key_path=key_path,
            chain_path=chain_path
        )
```

#### 2.5 Update SCEP Handler
**Modified: `scep.py`**
```python
# scep.py - Support both Vault and legacy modes

from vault_client import VaultClient

@scep_app.before_request
def load_ca():
    """Load CA using Vault or file-based keys based on config"""
    
    # Determine CA mode
    ca_mode = current_app.config.get('CA_MODE', 'RSA')
    if ca_mode == 'EC':
        key_path = current_app.config.get('SUBCA_KEY_PATH_EC')
        chain_path = current_app.config['CHAIN_FILE_PATH_EC']
        pki_path = current_app.config.get('VAULT_PKI_EC_PATH')
    else:
        key_path = current_app.config.get('SUBCA_KEY_PATH_RSA')
        chain_path = current_app.config['CHAIN_FILE_PATH_RSA']
        pki_path = current_app.config.get('VAULT_PKI_RSA_PATH')
    
    # Check if Vault is enabled
    vault = current_app.config.get('VAULT_CLIENT')
    
    if vault:
        # Vault mode: Create CA with Vault backend
        current_app.logger.debug("SCEP: Using Vault-backed CA")
        g.ca = CertificateAuthority(
            chain_path=chain_path,
            vault_client=vault,
            pki_path=pki_path,
            default_role='scep-enrollment'
        )
    else:
        # Legacy mode: Create CA with file-based keys
        current_app.logger.debug("SCEP: Using file-based CA")
        if not key_path or not os.path.exists(key_path):
            current_app.logger.error("CA key file not found: %s", key_path)
            abort(500, "CA not initialized")
        
        g.ca = CertificateAuthority(
            key_path=key_path,
            chain_path=chain_path
        )
```

#### 2.6 Update EST Handler
**Modified: `app.py` (EST endpoint)**
```python
@app.route("/.well-known/est/<path:operation>", methods=["POST", "GET"])
@requires_est_auth
def est_handler(operation):
    """EST protocol handler - Vault integrated"""
    
    if operation == "simpleenroll":
        # ... existing CSR parsing ...
        
        # Sign using Vault instead of OpenSSL subprocess
        cert = vault_client.sign_csr(
            csr=csr_obj,
            pki_path=app.config['VAULT_PKI_RSA_PATH'],
            role='est-enrollment',
            ttl=f"{validity_days * 24}h"
        )
        
        # Convert to PEM
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        
        # ... rest of response handling ...
```

#### 2.7 Update CRL Generation
**Modified: `app.py` (CRL endpoint)**
```python
@app.route("/api/crl/<ca_type>", methods=["GET"])
def get_crl_api(ca_type):
    """Get CRL from Vault PKI engine"""
    
    if ca_type.lower() == "rsa":
        pki_path = app.config['VAULT_PKI_RSA_PATH']
    elif ca_type.lower() == "ec":
        pki_path = app.config['VAULT_PKI_EC_PATH']
    else:
        return "Invalid CA type", 400
    
    try:
        crl_pem = vault_client.get_crl(pki_path)
        return Response(crl_pem, mimetype="application/pkix-crl")
    except Exception as e:
        app.logger.error(f"Failed to retrieve CRL: {e}")
        return "CRL generation failed", 500
```

#### 2.8 Update OCSP Responder
**Modified: `app.py` (OCSP endpoint)**
```python
@app.route("/ocsp", methods=["POST", "GET"])
def ocsp_responder():
    """OCSP responder with Vault signing"""
    
    # ... existing OCSP request parsing ...
    
    # Build OCSP response
    builder = OCSPResponseBuilder()
    # ... add response data ...
    
    # Sign using Vault Transit engine
    response_data = builder.build_without_signature()
    signature = vault_client.sign_data(
        transit_key=f"{pki_path}-ocsp",
        data=response_data
    )
    
    # Attach signature to response
    # ... finalize response ...
```

---

### Phase 3: Testing & Validation (Week 4)

#### 3.1 Unit Tests
**New File: `tests/test_vault_integration.py`**
```python
import pytest
from vault_client import VaultClient
from ca import CertificateAuthority


def test_vault_connection():
    """Test Vault connectivity"""
    vault = VaultClient(
        vault_addr="https://vault-test:8200",
        role_id=os.getenv("TEST_ROLE_ID"),
        secret_id=os.getenv("TEST_SECRET_ID")
    )
    assert vault.health_check()


def test_csr_signing():
    """Test CSR signing via Vault"""
    vault = VaultClient(...)
    ca = CertificateAuthority(
        chain_path="test-chain.pem",
        vault_client=vault,
        pki_path="pki-test"
    )
    
    # Generate test CSR
    csr = generate_test_csr()
    
    # Sign via Vault
    cert = ca.sign(csr, days=30)
    
    assert cert is not None
    assert cert.issuer == ca.certificate.subject


def test_private_key_isolation():
    """Ensure private key is never accessible"""
    vault = VaultClient(...)
    ca = CertificateAuthority(...)
    
    with pytest.raises(NotImplementedError):
        _ = ca.private_key
```

#### 3.2 Integration Tests
- SCEP enrollment with Vault backend
- EST enrollment with Vault backend
- CRL generation and validation
- OCSP response signing
- Performance benchmarks (Vault vs. local keys)

#### 3.3 Security Tests
- Attempt to extract private key (should fail)
- Verify audit logs in Vault
- Test key rotation without downtime
- Simulate Vault unavailability (fallback behavior)

---

### Phase 4: Deployment & Migration (Week 5)

#### 4.1 Pre-Deployment Checklist
- [ ] Vault cluster setup (HA recommended)
- [ ] Backup existing keys
- [ ] Test key migration in staging
- [ ] Configure Vault auto-unseal
- [ ] Setup monitoring and alerts
- [ ] Document rollback procedure

#### 4.2 Migration Steps
1. **Deploy updated code with Vault support** but keep `enabled=false`
2. **Test in legacy mode** to ensure backward compatibility
3. **Setup Vault infrastructure** in parallel
4. **Import keys to Vault** using secure migration tool
5. **Enable Vault in staging** by setting `enabled=true`
6. **Monitor staging for 48 hours** with comprehensive testing
7. **Gradual production rollout** (canary deployment recommended)
8. **Full production cutover** after validation
9. **Keep file-based keys as backup** for 30 days
10. **Securely destroy key files** after confidence period

#### Configuration Change Process
```bash
# Step 1: Current state (legacy mode)
[VAULT]
enabled = false

# Step 2: After Vault setup (gradual rollout)
[VAULT]
enabled = true  # Change this single line to switch modes
address = https://vault.prod.example.com:8200
# ... rest of Vault config

# Application automatically detects mode and uses appropriate backend
```

#### 4.3 Rollback Plan
```bash
# Emergency rollback procedure (zero downtime)

# Step 1: Edit config.ini
[VAULT]
enabled = false  # Single line change!

# Step 2: Restart application
./scripts/restart_server.ps1

# Step 3: Verify functionality
curl https://localhost:5000/api/health

# Application immediately reverts to file-based keys
# No code changes required!
```

**Rollback Safety:**
- Configuration-only change (no code deployment needed)
- File-based keys remain on disk during transition period
- Instant fallback capability
- No data loss or downtime

---

## ðŸ”’ Security Considerations

### Deployment Security Comparison

| Security Aspect | Same Server | Separate Server | Separate Vault Cluster |
|----------------|-------------|-----------------|------------------------|
| **Process Isolation** | âš ï¸ Shared OS | âœ… Full isolation | âœ… Full isolation |
| **Network Isolation** | âŒ Localhost only | âœ… Firewall rules | âœ… DMZ/separate network |
| **Compromise Impact** | âŒ Both affected | âœ… Limited blast radius | âœ… HA + limited blast |
| **Memory Attacks** | âš ï¸ Same kernel | âœ… Separate memory | âœ… Separate memory |
| **DDoS Resilience** | âŒ Affects both | âœ… Vault unaffected | âœ… Cluster redundancy |
| **Audit Independence** | âš ï¸ Same logs | âœ… Separate logs | âœ… Distributed audit |
| **Physical Security** | âŒ Single server | âœ… Can be in secure location | âœ… Geographic distribution |

### Why Separate Server is Recommended

**Defense in Depth Principle:**
```
Application Compromise â‰  Key Compromise

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ PKI Application â”‚  â† RCE vulnerability exploited
â”‚ (Compromised)   â”‚  
â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚ API calls only
         â”‚ (no direct key access)
         â†“
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Vault Server    â”‚  â† Keys remain safe
â”‚ (Isolated)      â”‚     - Different network segment
â”‚                 â”‚     - Separate authentication
â”‚                 â”‚     - Audit logs intact
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

**Same Server Risk:**
```
Application Compromise = Potential Key Compromise

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Same Server             â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”     â”‚
â”‚  â”‚ PKI App        â”‚     â”‚  â† Attacker gains root access
â”‚  â”‚ (Compromised)  â”‚     â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜     â”‚
â”‚         â†“               â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”     â”‚     Can potentially:
â”‚  â”‚ Vault Process  â”‚     â”‚     - Read memory
â”‚  â”‚                â”‚     â”‚     - Access unseal keys
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜     â”‚     - Modify audit logs
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

### Key Protection Mechanisms

| Layer | File-Based (Current) | Vault-Based (Proposed) |
|-------|---------------------|------------------------|
| **At-Rest Encryption** | OS filesystem encryption | Vault seal + AES-256-GCM |
| **In-Memory Protection** | Process memory (vulnerable) | Never leaves Vault |
| **Access Control** | File permissions | Granular policies + audit |
| **Secret Sharing** | None | Shamir 3-of-5 unseal |
| **Audit Trail** | Application logs only | Vault audit logs + app logs |
| **Key Rotation** | Manual, requires restart | Automated, zero-downtime |
| **Compromise Detection** | Difficult | Real-time Vault alerts |

### Threat Model Improvements

| Threat | Current Risk | Vault-Mitigated Risk |
|--------|-------------|---------------------|
| Memory dump attack | **HIGH** - Key exposed | **LOW** - Key never in app memory |
| Filesystem compromise | **HIGH** - Direct key access | **LOW** - Keys encrypted in Vault |
| Insider threat | **MEDIUM** - File access | **LOW** - MFA + audit required |
| Application vulnerability | **HIGH** - RCE = key theft | **LOW** - Can't extract sealed keys |
| Key exfiltration | **HIGH** - Copy file | **LOW** - Vault seal prevents export |

---

## ðŸ“Š Performance Impact Analysis

### Expected Latency Increases

| Operation | Current (ms) | With Vault (ms) | Increase |
|-----------|-------------|----------------|----------|
| Certificate Signing | 5-10 | 15-25 | +10-15ms |
| SCEP Enrollment | 50-100 | 75-150 | +50% |
| CRL Generation | 100-200 | 120-250 | +20-50ms |
| OCSP Response | 5-10 | 15-30 | +10-20ms |

**Mitigation Strategies**:
- Implement response caching where appropriate
- Use Vault's batch signing APIs for bulk operations
- Deploy Vault close to application (same datacenter)
- Consider Vault Performance Standby nodes for read scaling

---

## ðŸ”„ Post-Quantum Cryptography (PQC) Support

### Vault Transit Engine for PQC

Vault's Transit engine supports custom signing operations, enabling PQC algorithms:

```bash
# Create PQC signing key in Transit
vault write transit/keys/pqc-mldsa44 \
    type=rsa-4096 \
    exportable=false \
    allow_plaintext_backup=false

# Import existing PQC key (if supported in future Vault versions)
vault write transit/keys/pqc-dilithium3/import \
    type=dilithium3 \
    public_key=@dilithium3.pub \
    private_key=@dilithium3.key
```

### Hybrid Signatures (Classical + PQC)

For maximum security during the PQC transition:
```python
def hybrid_sign(data: bytes) -> Tuple[bytes, bytes]:
    """Dual-sign with RSA and Dilithium"""
    rsa_sig = vault.sign_data("rsa-key", data)
    pqc_sig = vault.sign_data("pqc-mldsa44", data)
    return rsa_sig, pqc_sig
```

---

## ðŸ“ˆ Monitoring & Operations

### Vault Health Metrics
- Seal status (sealed/unsealed)
- Token TTL and renewal
- PKI engine certificate issuance rate
- Transit engine signing latency
- Audit log volume

### Application Integration Metrics
- Vault API call success/failure rate
- Average signing latency
- Vault connection pool status
- Cache hit/miss ratio (for CRL/OCSP)

### Alerts
- ðŸš¨ **CRITICAL**: Vault sealed or unreachable
- âš ï¸ **WARNING**: Token expiring in < 5 minutes
- âš ï¸ **WARNING**: Signing latency > 100ms
- â„¹ï¸ **INFO**: Key rotation completed

---

## ðŸ’° Cost-Benefit Analysis

### Implementation Costs
- **Development Time**: 4-5 weeks (1 developer)
- **Infrastructure**: Vault Enterprise license (optional) or OSS version
- **Training**: 2-3 days for ops team
- **Testing**: 1 week comprehensive testing

### Benefits
- âœ… **Security**: HSM-like protection without hardware costs
- âœ… **Compliance**: Meets key isolation requirements for many standards
- âœ… **Auditability**: Complete signing operation audit trail
- âœ… **Scalability**: Centralized key management for multiple CAs
- âœ… **Flexibility**: Easy key rotation and policy updates

---

## ðŸš€ Future Enhancements

1. **Multi-Region Vault Replication** for DR
2. **Auto-Unseal with Cloud KMS** (AWS, Azure, GCP)
3. **Dynamic Vault Policies** based on certificate subject
4. **Vault Agent Sidecar** for automatic token renewal
5. **Full PQC Support** when Vault adds native Dilithium/Kyber
6. **Certificate Templates in Vault** for consistent issuance
7. **Automated Key Rotation Schedule**

---

## ðŸ“š References

- [HashiCorp Vault PKI Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/pki)
- [Vault Transit Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [PKCS#11 HSM Interface](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)

---

## âœ… Success Criteria

- [ ] CA private keys removed from filesystem
- [ ] All signing operations use Vault APIs
- [ ] Zero private key material in application memory
- [ ] Comprehensive audit logs for all key operations
- [ ] Performance degradation < 30% for critical paths
- [ ] Automated key rotation working
- [ ] PQC signing operational
- [ ] Security audit passes
- [ ] Documentation complete
- [ ] Team trained on Vault operations

---

**Document Version**: 1.0  
**Date**: December 5, 2025  
**Author**: pkisquire CA Team  
**Status**: Planning Phase

