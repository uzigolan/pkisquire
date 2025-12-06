import os
import configparser
from typing import Union, Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


def load_vault_config(config_path: str = 'config.ini') -> Dict[str, Any]:
    """
    Load Vault configuration from config.ini [VAULT] section.
    
    Args:
        config_path: Path to config.ini file
        
    Returns:
        Dictionary with Vault configuration settings
    """
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
        if '${' in role_id_var:
            vault_config['role_id'] = os.environ.get('VAULT_ROLE_ID')
        else:
            vault_config['role_id'] = role_id_var
            
        if '${' in secret_id_var:
            vault_config['secret_id'] = os.environ.get('VAULT_SECRET_ID')
        else:
            vault_config['secret_id'] = secret_id_var
        
        # PKI paths
        vault_config['pki_rsa_path'] = config.get('VAULT', 'pki_rsa_path', fallback='pki-subca-rsa')
        vault_config['pki_ec_path'] = config.get('VAULT', 'pki_ec_path', fallback='pki-subca-ec')
        vault_config['transit_path'] = config.get('VAULT', 'transit_path', fallback='transit')
        
        # Connection settings
        vault_config['timeout'] = config.getint('VAULT', 'timeout', fallback=30)
        vault_config['retry_attempts'] = config.getint('VAULT', 'retry_attempts', fallback=3)
        
        # TLS settings
        vault_config['verify_ssl'] = config.getboolean('VAULT', 'verify_ssl', fallback=True)
        ca_cert = config.get('VAULT', 'ca_cert_path', fallback='')
        vault_config['ca_cert_path'] = ca_cert if ca_cert else None
        
        # Vault roles
        vault_config['role_scep'] = config.get('VAULT', 'role_scep', fallback='scep-enrollment')
        vault_config['role_est'] = config.get('VAULT', 'role_est', fallback='est-enrollment')
        vault_config['role_default'] = config.get('VAULT', 'role_default', fallback='server-cert')
    else:
        # No VAULT section = disabled by default
        vault_config['enabled'] = False
    
    return vault_config


class ConfigStorage:
    """
    Loads CA key, sub-CA cert and chain directly from paths in app config.
    Read-only: does NOT generate or persist anything except serial if configured.
    """

    def __init__(
        self,
        key_path: str,
        cert_path: str,
        chain_path: str,
        serial_path: str = None,
        password: Union[bytes, None] = None
    ):
        self._key_path = key_path
        self._cert_path = cert_path
        self._chain_path = chain_path
        self._serial_path = serial_path
        self._password = password

    def exists(self) -> bool:
        """Do both key and cert files exist?"""
        return os.path.exists(self._key_path) and os.path.exists(self._cert_path)

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        """Load and return the CA’s private key (PEM)."""
        data = open(self._key_path, "rb").read()
        return serialization.load_pem_private_key(
            data, password=self._password, backend=default_backend()
        )

    @property
    def ca_certificate(self) -> x509.Certificate:
        """Load and return the CA certificate (PEM)."""
        data = open(self._cert_path, "rb").read()
        return x509.load_pem_x509_certificate(data, default_backend())

    @property
    def full_chain(self) -> x509.Certificate:
        """If you need the entire chain file, you can load it here."""
        data = open(self._chain_path, "rb").read()
        # If it’s multiple PEMs back-to-back, you could split on “-----BEGIN CERTIFICATE-----”
        return x509.load_pem_x509_certificate(data, default_backend())

    @property
    def serial(self) -> int:
        """
        Read the current serial number from a file, if configured.
        Returns 0 if no serial_path or file doesn’t exist.
        """
        if self._serial_path and os.path.exists(self._serial_path):
            return int(open(self._serial_path).read().strip())
        return 0

    @serial.setter
    def serial(self, value: int):
        """
        Persist the new serial number.
        Raises if no serial_path was given.
        """
        if not self._serial_path:
            raise RuntimeError("ConfigStorage: no serial_path configured")
        with open(self._serial_path, "w") as fd:
            fd.write(str(value))

    def save_issued_certificate(self, certificate: x509.Certificate):
        """
        Stub: ConfigStorage is read-only for issued cert tracking.
        If you need to save each issued cert, override this method.
        """
        raise RuntimeError("ConfigStorage: cannot persist issued certificates")

    def fetch_issued_certificate(self, serial: int) -> x509.Certificate:
        """
        Stub: ConfigStorage doesn’t look up stored certificates.
        If you keep them elsewhere (DB, FS), implement here.
        """
        raise RuntimeError("ConfigStorage: fetch_issued_certificate not implemented")

