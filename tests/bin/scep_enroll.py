#!/usr/bin/env python3
"""
Full SCEP Enrollment Client - properly wraps CSR in encrypted PKCS#7
"""
import sys
import os

# Add workspace root to Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
workspace_root = os.path.dirname(os.path.dirname(script_dir))
sys.path.insert(0, workspace_root)

import argparse
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs7

# Import from your existing SCEP modules
from envelope import PKCSPKIEnvelopeBuilder
from builders import PKIMessageBuilder, Signer
from enums import MessageType


def enroll_scep(url, key_file, csr_file, ca_cert_file, output_file, verbose=False):
    """Enroll certificate using proper SCEP protocol"""
    
    # 1. Load private key
    if verbose:
        print(f"[*] Loading private key from: {key_file}")
    with open(key_file, 'rb') as f:
        key_data = f.read()
    private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
    
    # 2. Load CSR
    if verbose:
        print(f"[*] Loading CSR from: {csr_file}")
    with open(csr_file, 'rb') as f:
        csr_data = f.read()
    csr = x509.load_pem_x509_csr(csr_data, default_backend())
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    
    # 3. Load CA certificate
    if verbose:
        print(f"[*] Loading CA certificate from: {ca_cert_file}")
    with open(ca_cert_file, 'rb') as f:
        ca_cert_data = f.read()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())
    
    # 4. Create self-signed certificate for the request (temporary)
    if verbose:
        print("[*] Creating temporary self-signed certificate for SCEP request...")
    from datetime import datetime, timedelta
    temp_cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        csr.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=1)
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # 5. Build SCEP PKIMessage (encrypted envelope)
    if verbose:
        print("[*] Building encrypted SCEP PKIMessage...")
    
    # Create envelope with CSR
    envelope_builder = PKCSPKIEnvelopeBuilder()
    envelope_builder.encrypt(csr_der, algorithm='3des')
    envelope_builder.add_recipient(ca_cert)
    envelope, sym_key, iv = envelope_builder.finalize()  # Returns tuple
    
    # Create signed PKIMessage
    signer = Signer(temp_cert, private_key, 'sha256')
    pki_msg_builder = PKIMessageBuilder()
    pki_msg_builder.message_type(MessageType.PKCSReq)
    pki_msg_builder.sender_nonce()
    pki_msg_builder.add_signer(signer)
    pki_msg_builder.pki_envelope(envelope)
    
    pki_msg = pki_msg_builder.finalize()
    pki_msg_der = pki_msg.dump()  # Convert to bytes
    
    # 6. Send to server
    if verbose:
        print(f"[*] Sending enrollment request to: {url}")
    
    import base64
    message_b64 = base64.b64encode(pki_msg_der).decode('ascii')
    
    # Try POST first (server advertises POSTPKIOperation)
    response = requests.post(
        f"{url}?operation=PKIOperation",
        data=pki_msg_der,
        headers={'Content-Type': 'application/x-pki-message'},
        verify=False
    )
    
    if response.status_code == 200:
        if verbose:
            print("[+] Enrollment successful!")
        
        # Save raw response for debugging
        with open('tests/results/scep_response.bin', 'wb') as f:
            f.write(response.content)
        if verbose:
            print(f"[*] Saved response to tests/results/scep_response.bin ({len(response.content)} bytes)")
        
        # Parse SCEP response using SCEPMessage parser
        # NOTE: Cannot use pkcs7.load_der_pkcs7_certificates() because that extracts
        # from the outer SignedData (which contains CA cert), not the inner degenerate
        # PKCS#7 that contains the issued certificate
        try:
            from message import SCEPMessage
            resp_msg = SCEPMessage.parse(response.content)
            
            if verbose:
                print(f"[*] PKI Status: {resp_msg.pki_status}")
            
            if resp_msg.pki_status == '0':  # SUCCESS (it's a string)
                # Get decrypted envelope data (degenerate PKCS#7 with certificate)
                cert_pkcs7_der = resp_msg.get_decrypted_envelope_data(temp_cert, private_key)
                
                if verbose:
                    print(f"[*] Decrypted envelope data: {len(cert_pkcs7_der)} bytes")
                
                # Parse the degenerate PKCS#7 to extract the certificate
                try:
                    # The decrypted data is a degenerate PKCS#7 containing only the issued cert
                    certs = pkcs7.load_der_pkcs7_certificates(cert_pkcs7_der)
                    if certs:
                        cert = certs[0]  # Get the issued certificate
                        if verbose:
                            print(f"[*] Extracted certificate from PKCS#7")
                    else:
                        print("[-] No certificates found in PKCS#7 response")
                        return False
                except Exception as e:
                    if verbose:
                        print(f"[*] Could not parse as PKCS#7, trying as raw certificate: {e}")
                    # Fallback: try to parse as raw certificate
                    cert = x509.load_der_x509_certificate(cert_pkcs7_der, default_backend())
                
                # Write certificate
                cert_pem = cert.public_bytes(serialization.Encoding.PEM)
                with open(output_file, 'wb') as f:
                    f.write(cert_pem)
                
                print(f"[+] Certificate saved to: {output_file}")
                print(f"    Subject: {cert.subject.rfc4514_string()}")
                print(f"    Serial: {hex(cert.serial_number)}")
                return True
            else:
                print(f"[-] Enrollment failed with status: {resp_msg.pki_status}")
                if hasattr(resp_msg, 'fail_info'):
                    print(f"    Fail Info: {resp_msg.fail_info}")
                return False
                
        except Exception as e:
            print(f"[-] Error parsing response: {e}")
            import traceback
            traceback.print_exc()
            return False
    else:
        print(f"[-] Enrollment failed: HTTP {response.status_code}")
        print(f"    Response: {response.text[:200]}")
        return False


def main():
    parser = argparse.ArgumentParser(description='SCEP Enrollment Client')
    parser.add_argument('-u', '--url', required=True, help='SCEP server URL')
    parser.add_argument('-k', '--key', required=True, help='Private key file')
    parser.add_argument('-r', '--csr', required=True, help='CSR file')
    parser.add_argument('-c', '--ca-cert', required=True, help='CA certificate file')
    parser.add_argument('-l', '--output', required=True, help='Output certificate file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    success = enroll_scep(
        args.url,
        args.key,
        args.csr,
        args.ca_cert,
        args.output,
        args.verbose
    )
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
