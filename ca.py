# ca.py

import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from asn1crypto import x509 as asn1_x509
from asn1crypto.cms import SignerIdentifier, IssuerAndSerialNumber

class CertificateAuthority:
    def __init__(self, key_path: str, chain_path: str):
        # load private key
        with open(key_path, "rb") as f:
            self._private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        # load first cert from chain
        with open(chain_path, "rb") as f:
            pem_chain = f.read()
        first_pem = pem_chain.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
        self._certificate = x509.load_pem_x509_certificate(first_pem, default_backend())

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        return self._private_key

    @property
    def certificate(self) -> x509.Certificate:
        return self._certificate

    def signer_identifier(self) -> bytes:
        """
        Build a full IssuerAndSerialNumber structure with both
        issuer *and* serial, and wrap in SignerIdentifier.
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
             hash_alg=hashes.SHA256) -> x509.Certificate:
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

