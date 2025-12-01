# 🔡 RAD PKI Certificate Authority Server

Welcome to the RAD CA Server — a Flask-based Public Key Infrastructure (PKI) platform designed for managing certificate lifecycles, securing MQTT brokers, and supporting quantum-safe key algorithms! Pika Pi! ⚡

---

## 🔍 Overview

This server provides tools for:

* Generating RSA, ECC, and quantum-safe keys
* Submitting and signing Certificate Signing Requests (CSR)
* Managing issued certificates (view, revoke, delete)
* Downloading CA chains and Certificate Revocation Lists (CRLs)
* Real-time certificate validation via OCSP
* Enrolling devices using EST (SCEP in development)
* TLS authentication for MQTT with CRL enforcement

---

## 🚀 Features

* 📄 Web UI + RESTful API support
* 🔒 CSR submission and certificate issuance
* 📄 Certificate revocation and CRL generation
* 🌐 EST-based automated enrollment
* ⚛️ Post-Quantum Cryptography (e.g., Dilithium)
* 📡 MQTTs TLS integration
* ✅ OCSP real-time validation

---

## 🛠️ Installation

> **Requirements**: Rocky Linux 9.x, Python 3, Flask, OpenSSL, oqs-provider

### 1. Clone the repo and install dependencies:

```bash
sudo dnf install python3
pip install Flask cryptography asn1crypto
```

### 2. Extract and set up the server:

```bash
tar xvfz pki_server_1.tar.gz
cd pki-server
python app.py
```

### 3. (Optional) Enable Quantum-Safe provider:

```bash
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
./scripts/fullbuild.sh
sudo cmake --install _build
```

---

## 🌐 Web Access

Access the server via:

```
https://openxpki.iot-rad.com:4443/
```

---

## 📎 License

> This software is proprietary and confidential. Unauthorized use, copying, or distribution is strictly prohibited without prior written consent from RAD Data Communications Ltd.

---

## ⚡ Pikachu Says...

Stay secure, and may your certs never expire! Pika Pi! 💛

---

## 👤 User Management

- Supports multi-user accounts with roles: admin and user.
- Admins can approve, deactivate, activate, and manage users via the web UI.
- Each certificate, key, and profile is associated with a user (ownership enforced).
- Only admins can manage all resources; users can only view/manage their own.
- User status (active, deactivated, pending) is enforced at login and visible in the admin UI.
- Registration, login, and logout are available from the web interface.

---

## 🗄️ Database Initialization & Migration

### Initialize a New Database

To create a new database with all required tables and a default admin user:

```bash
python init_db.py
```

- Reads configuration from `config.ini` (including admin user credentials).
- Creates all tables and the initial admin user if not present.

### Migrate an Existing Database

To migrate an old database (e.g., certs.db) to the latest schema, including user table and admin user:

```bash
python migrate_db.py
```

- Adds missing columns (e.g., user_id) to existing tables if needed.
- Creates the users table and admin user if missing.
- Safe to run multiple times (idempotent).
