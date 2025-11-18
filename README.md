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
