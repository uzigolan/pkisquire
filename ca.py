# ca.py

import datetime
import logging
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from asn1crypto import x509 as asn1_x509
from asn1crypto.cms import SignerIdentifier, IssuerAndSerialNumber

logger = logging.getLogger(__name__)

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

    def signer_identifier(self) -> bytes:
        """
        Build a full IssuerAndSerialNumber structure with both
        issuer *and* serial, and wrap in SignerIdentifier.
        Works in both Vault and legacy modes.
        """
        # grab DER of the CA cert
        der = self.certificate.public_bytes(serialization.Encoding.DER)
        # parse asn1crypto cert
        asn1cert = asn1_x509.Certificate.load(der)
        ias = IssuerAndSerialNumber({
            'issuer': asn1cert.issuer,
            'serial_number': asn1cert.serial_number
        })
        sid = SignerIdentifier('issuer_and_serial_number', ias)
        return sid.dump()

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
            logger.info(f"🔐 VAULT MODE: Signing CSR via Vault PKI engine")
            logger.debug(f"  → PKI Path: {self._pki_path}")
            logger.debug(f"  → Role: {role or self._default_role}")
            logger.debug(f"  → TTL: {days * 24}h")
            logger.debug(f"  → Subject: {csr.subject.rfc4514_string()}")
            
            ttl = f"{days * 24}h"
            role = role or self._default_role
            
            result = self._vault.sign_csr(
                csr=csr,
                pki_path=self._pki_path,
                role=role,
                ttl=ttl,
                extensions=extensions
            )
            
            logger.info(f"✓ VAULT MODE: Certificate signed successfully via Vault")
            logger.debug(f"  → Serial: {result.serial_number}")
            return result
        else:
            # Legacy mode: Sign with local private key
            logger.info(f"📁 LEGACY MODE: Signing CSR with local private key")
            logger.debug(f"  → Subject: {csr.subject.rfc4514_string()}")
            logger.debug(f"  → Validity: {days} days")
            
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
            
            result = builder.sign(self.private_key, hash_alg(), default_backend())
            logger.info(f"✓ LEGACY MODE: Certificate signed with local key")
            logger.debug(f"  → Serial: {result.serial_number}")
            return result

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
            logger.info(f"🔐 VAULT MODE: Signing data via Vault Transit engine")
            logger.debug(f"  → Transit Key: {transit_key}")
            logger.debug(f"  → Data Length: {len(data)} bytes")
            
            result = self._vault.sign_data(transit_key, data)
            logger.info(f"✓ VAULT MODE: Data signed successfully via Vault")
            return result
        else:
            # Legacy mode: Use cryptography library for signing
            logger.info(f"📁 LEGACY MODE: Signing data with local private key")
            logger.debug(f"  → Data Length: {len(data)} bytes")
            
            result = self.private_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            logger.info(f"✓ LEGACY MODE: Data signed with local key")
            return result


