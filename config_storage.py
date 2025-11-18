import os
from typing import Union
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

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

