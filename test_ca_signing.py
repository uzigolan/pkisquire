#!/usr/bin/env python3
"""
Test script to demonstrate CA signing with debug logging.
This shows the Vault vs Legacy mode logging.
"""

import sys
import logging
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Configure logging to see DEBUG messages
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s'
)

from ca import CertificateAuthority
from vault_client import VaultClient
from config_storage import load_vault_config

def test_legacy_signing():
    """Test legacy file-based signing"""
    print("\n" + "="*60)
    print("TEST 1: Legacy Mode (file-based signing)")
    print("="*60 + "\n")
    
    ca = CertificateAuthority(
        key_path="pki-subca/rad_ca_sub_rsa.key",
        chain_path="pki-subca/rad_chain_rsa.crt"
    )
    
    # Load a test CSR
    with open("test_csr.pem", "rb") as f:
        csr_pem = f.read()
    
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())
    
    # Sign it
    cert = ca.sign(csr, days=365)
    
    print(f"\n✓ Signed certificate serial: {hex(cert.serial_number)}")
    print(f"✓ Subject: {cert.subject.rfc4514_string()}")
    

def test_vault_signing():
    """Test Vault-based signing"""
    print("\n" + "="*60)
    print("TEST 2: Vault Mode (Vault PKI signing)")
    print("="*60 + "\n")
    
    # Load Vault config
    vault_config = load_vault_config()
    
    if not vault_config.get('enabled'):
        print("⚠ Vault is disabled in config.ini - skipping Vault test")
        return
    
    try:
        # Initialize Vault client
        vault_client = VaultClient(
            address=vault_config['address'],
            role_id=vault_config['role_id'],
            secret_id=vault_config['secret_id']
        )
        
        # Create CA in Vault mode
        ca = CertificateAuthority(
            vault_client=vault_client,
            pki_path=vault_config['pki_rsa_path'],
            default_role="scep-enrollment"
        )
        
        # Load a test CSR
        with open("test_csr.pem", "rb") as f:
            csr_pem = f.read()
        
        csr = x509.load_pem_x509_csr(csr_pem, default_backend())
        
        # Sign it
        cert = ca.sign(csr, days=365)
        
        print(f"\n✓ Signed certificate serial: {hex(cert.serial_number)}")
        print(f"✓ Subject: {cert.subject.rfc4514_string()}")
        
    except Exception as e:
        print(f"\n✗ Vault signing failed: {e}")
        print("This is expected if Vault PKI doesn't have CA keys configured yet")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("CA SIGNING DEBUG TEST")
    print("="*60)
    
    # Run both tests
    test_legacy_signing()
    test_vault_signing()
    
    print("\n" + "="*60)
    print("TESTS COMPLETE")
    print("="*60 + "\n")
