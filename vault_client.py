"""
HashiCorp Vault integration for CA operations.
Provides key isolation and secure signing operations.
"""
import hvac
import base64
import logging
from typing import Optional, Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


class VaultClient:
    """Wrapper for HashiCorp Vault PKI and Transit operations"""
    
    def __init__(self, 
                 vault_addr: str, 
                 role_id: str, 
                 secret_id: str,
                 verify_ssl: bool = True,
                 ca_cert: Optional[str] = None,
                 timeout: int = 30):
        """
        Initialize Vault client with AppRole authentication
        
        Args:
            vault_addr: Vault server address (e.g., https://127.0.0.1:8200)
            role_id: AppRole role ID
            secret_id: AppRole secret ID
            verify_ssl: Verify SSL certificates
            ca_cert: Path to CA certificate for SSL verification
            timeout: Request timeout in seconds
        """
        self.logger = logging.getLogger(__name__)
        self.vault_addr = vault_addr
        
        # Create Vault client
        self.client = hvac.Client(
            url=vault_addr,
            verify=ca_cert if ca_cert else verify_ssl,
            timeout=timeout
        )
        
        # Authenticate with AppRole
        try:
            self.client.auth.approle.login(
                role_id=role_id,
                secret_id=secret_id
            )
            self.logger.info(f"Authenticated with Vault at {vault_addr}")
        except Exception as e:
            self.logger.error(f"Failed to authenticate with Vault: {e}")
            raise
    
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
            ttl: Certificate validity period (e.g., "8760h" for 1 year)
            extensions: Additional x509 extensions (not implemented yet)
            
        Returns:
            Signed x509.Certificate object
            
        Raises:
            Exception: If signing fails
        """
        try:
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
            
            response = self.client.write(
                f"{pki_path}/sign/{role}",
                csr=csr_pem,
                ttl=ttl,
                format="pem"
            )
            
            if not response or 'data' not in response:
                raise Exception("Invalid response from Vault PKI sign operation")
            
            cert_pem = response['data']['certificate']
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(),
                default_backend()
            )
            
            self.logger.debug(f"Successfully signed certificate via Vault PKI: {pki_path}/sign/{role}")
            return cert
            
        except Exception as e:
            self.logger.error(f"Failed to sign CSR with Vault: {e}")
            raise
    
    def get_ca_certificate(self, pki_path: str) -> x509.Certificate:
        """
        Retrieve CA certificate from Vault
        
        Args:
            pki_path: Vault PKI mount path
            
        Returns:
            CA certificate
        """
        try:
            response = self.client.read(f"{pki_path}/cert/ca")
            
            if not response or 'data' not in response:
                raise Exception("Invalid response from Vault")
            
            cert_pem = response['data']['certificate']
            return x509.load_pem_x509_certificate(
                cert_pem.encode(),
                default_backend()
            )
        except Exception as e:
            self.logger.error(f"Failed to retrieve CA certificate from Vault: {e}")
            raise
    
    def get_crl(self, pki_path: str) -> bytes:
        """
        Retrieve CRL from Vault PKI engine
        
        Args:
            pki_path: Vault PKI mount path
            
        Returns:
            CRL in PEM format
        """
        try:
            response = self.client.read(f"{pki_path}/crl/pem")
            
            if not response or 'data' not in response:
                raise Exception("Invalid response from Vault")
            
            return response['data']['crl'].encode()
        except Exception as e:
            self.logger.error(f"Failed to retrieve CRL from Vault: {e}")
            raise
    
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
        try:
            # Base64 encode the data
            data_b64 = base64.b64encode(data).decode()
            
            response = self.client.write(
                f"transit/sign/{transit_key}",
                input=data_b64,
                hash_algorithm=hash_algorithm,
                signature_algorithm="pkcs1v15"
            )
            
            if not response or 'data' not in response:
                raise Exception("Invalid response from Vault Transit sign")
            
            # Vault returns signature in format "vault:v1:base64sig"
            sig_parts = response['data']['signature'].split(':')
            sig_b64 = sig_parts[-1]
            return base64.b64decode(sig_b64)
            
        except Exception as e:
            self.logger.error(f"Failed to sign data with Vault Transit: {e}")
            raise
    
    def rotate_key(self, transit_key: str):
        """
        Rotate a transit encryption key
        
        Args:
            transit_key: Transit key name
        """
        try:
            self.client.write(f"transit/keys/{transit_key}/rotate")
            self.logger.info(f"Rotated transit key: {transit_key}")
        except Exception as e:
            self.logger.error(f"Failed to rotate transit key: {e}")
            raise
    
    def health_check(self) -> bool:
        """
        Check Vault connectivity and authentication
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            if not self.client.sys.is_initialized():
                self.logger.error("Vault is not initialized")
                return False
            
            if not self.client.is_authenticated():
                self.logger.error("Vault client is not authenticated")
                return False
            
            # Try to read sys/health
            health = self.client.sys.read_health_status(method='GET')
            if health.get('sealed', True):
                self.logger.error("Vault is sealed")
                return False
            
            self.logger.debug("Vault health check passed")
            return True
            
        except Exception as e:
            self.logger.error(f"Vault health check failed: {e}")
            return False
    
    def renew_token(self):
        """Renew the current authentication token"""
        try:
            self.client.auth.token.renew_self()
            self.logger.debug("Vault token renewed")
        except Exception as e:
            self.logger.error(f"Failed to renew Vault token: {e}")
            raise
