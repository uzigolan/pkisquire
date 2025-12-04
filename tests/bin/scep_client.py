#!/usr/bin/env python3
"""
SCEP Client for testing SCEP server
"""
import os
import sys

# Add workspace root to Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
workspace_root = os.path.dirname(os.path.dirname(script_dir))
sys.path.insert(0, workspace_root)

import argparse
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs7
import base64
from datetime import datetime, timedelta


class SCEPClient:
    def __init__(self, server_url, ca_identifier=None):
        self.server_url = server_url.rstrip('/')
        self.ca_identifier = ca_identifier
        self.ca_cert = None
        self.private_key = None
        self.csr = None
        
    def get_ca_caps(self):
        """Get CA capabilities"""
        url = f"{self.server_url}?operation=GetCACaps"
        if self.ca_identifier:
            url += f"&message={self.ca_identifier}"
        
        print(f"[*] Getting CA capabilities from: {url}")
        response = requests.get(url, verify=False)
        
        if response.status_code == 200:
            caps = response.text.strip().split('\n')
            print(f"[+] CA Capabilities: {caps}")
            return caps
        else:
            print(f"[-] Failed to get CA capabilities: {response.status_code}")
            return None
    
    def get_ca_cert(self):
        """Get CA certificate"""
        url = f"{self.server_url}?operation=GetCACert"
        if self.ca_identifier:
            url += f"&message={self.ca_identifier}"
        
        print(f"[*] Getting CA certificate from: {url}")
        response = requests.get(url, verify=False)
        
        if response.status_code == 200:
            # The response could be a single cert or a PKCS#7 chain
            content_type = response.headers.get('Content-Type', '')
            
            if 'application/x-x509-ca-cert' in content_type:
                # Single certificate
                self.ca_cert = x509.load_der_x509_certificate(response.content, default_backend())
                print(f"[+] Got CA certificate: {self.ca_cert.subject}")
            elif 'application/x-x509-ca-ra-cert' in content_type:
                # PKCS#7 chain
                certs = pkcs7.load_der_pkcs7_certificates(response.content)
                if certs:
                    self.ca_cert = certs[0]  # Use first cert as CA
                    print(f"[+] Got CA certificate chain, using: {self.ca_cert.subject}")
            else:
                # Try to parse as DER cert
                try:
                    self.ca_cert = x509.load_der_x509_certificate(response.content, default_backend())
                    print(f"[+] Got CA certificate: {self.ca_cert.subject}")
                except:
                    print(f"[-] Unknown content type: {content_type}")
                    return None
            
            return self.ca_cert
        else:
            print(f"[-] Failed to get CA certificate: {response.status_code}")
            return None
    
    def load_key(self, key_file, password=None):
        """Load private key from file"""
        print(f"[*] Loading private key from: {key_file}")
        with open(key_file, 'rb') as f:
            key_data = f.read()
        
        try:
            if password:
                self.private_key = serialization.load_pem_private_key(
                    key_data, password=password.encode(), backend=default_backend()
                )
            else:
                self.private_key = serialization.load_pem_private_key(
                    key_data, password=None, backend=default_backend()
                )
            print(f"[+] Loaded private key")
            return self.private_key
        except Exception as e:
            print(f"[-] Failed to load key: {e}")
            return None
    
    def load_csr(self, csr_file):
        """Load CSR from file"""
        print(f"[*] Loading CSR from: {csr_file}")
        with open(csr_file, 'rb') as f:
            csr_data = f.read()
        
        try:
            self.csr = x509.load_pem_x509_csr(csr_data, default_backend())
            print(f"[+] Loaded CSR for: {self.csr.subject}")
            return self.csr
        except Exception as e:
            print(f"[-] Failed to load CSR: {e}")
            return None
    
    def generate_key_and_csr(self, common_name, key_size=2048, **subject_attrs):
        """Generate private key and CSR"""
        print(f"[*] Generating {key_size}-bit RSA key...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Build subject name
        name_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
        
        if subject_attrs.get('country'):
            name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject_attrs['country']))
        if subject_attrs.get('state'):
            name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_attrs['state']))
        if subject_attrs.get('locality'):
            name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, subject_attrs['locality']))
        if subject_attrs.get('organization'):
            name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_attrs['organization']))
        if subject_attrs.get('organizational_unit'):
            name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_attrs['organizational_unit']))
        
        print(f"[*] Generating CSR for: {common_name}")
        self.csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(name_attributes)
        ).sign(self.private_key, hashes.SHA256(), default_backend())
        
        print(f"[+] Generated CSR")
        return self.csr
    
    def pkcs_req(self, challenge_password=None):
        """Send PKCSReq to enroll certificate"""
        if not self.ca_cert:
            print("[-] CA certificate not available. Run get_ca_cert() first.")
            return None
        
        if not self.csr:
            print("[-] CSR not available. Run generate_key_and_csr() first.")
            return None
        
        print("[*] Creating PKCS#7 request...")
        
        # For SCEP, we need to create a self-signed certificate for the request
        # This is a temporary cert just for the enrollment
        temp_cert = x509.CertificateBuilder().subject_name(
            self.csr.subject
        ).issuer_name(
            self.csr.subject
        ).public_key(
            self.csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=1)
        ).sign(self.private_key, hashes.SHA256(), default_backend())
        
        # Create PKCS#7 signed data with CSR
        # Note: This is simplified - full SCEP requires proper PKCS#7 wrapping
        csr_der = self.csr.public_bytes(serialization.Encoding.DER)
        
        # Base64 encode the CSR for the message parameter
        message = base64.b64encode(csr_der).decode('ascii')
        
        url = f"{self.server_url}?operation=PKCSReq&message={message}"
        
        print(f"[*] Sending enrollment request to: {self.server_url}")
        response = requests.post(url, 
                                data=csr_der,
                                headers={'Content-Type': 'application/pkcs7-mime'},
                                verify=False)
        
        if response.status_code == 200:
            print(f"[+] Enrollment successful!")
            # Parse the response (should be PKCS#7 with certificate)
            try:
                # Try to extract certificate from response
                certs = pkcs7.load_der_pkcs7_certificates(response.content)
                if certs:
                    print(f"[+] Received certificate: {certs[0].subject}")
                    return certs[0]
                else:
                    print("[+] Response received but no certificates found")
                    return response.content
            except Exception as e:
                print(f"[!] Could not parse certificate response: {e}")
                return response.content
        else:
            print(f"[-] Enrollment failed: {response.status_code}")
            print(f"    Response: {response.text[:200]}")
            return None
    
    def save_key(self, filename, password=None):
        """Save private key to file"""
        if not self.private_key:
            print("[-] No private key to save")
            return False
        
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()
        
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption
        )
        
        with open(filename, 'wb') as f:
            f.write(pem)
        
        print(f"[+] Saved private key to: {filename}")
        return True
    
    def save_cert(self, cert, filename):
        """Save certificate to file"""
        if not cert:
            print("[-] No certificate to save")
            return False
        
        if isinstance(cert, x509.Certificate):
            pem = cert.public_bytes(serialization.Encoding.PEM)
        else:
            pem = cert
        
        with open(filename, 'wb') as f:
            f.write(pem)
        
        print(f"[+] Saved certificate to: {filename}")
        return True


def main():
    parser = argparse.ArgumentParser(description='SCEP Client for certificate enrollment')
    parser.add_argument('-u', '--url', required=True, help='SCEP server URL (e.g., http://localhost:5000/scep)')
    parser.add_argument('-c', '--ca-cert', help='CA certificate file (for enrollment validation)')
    parser.add_argument('-k', '--key', help='Private key file (use existing key)')
    parser.add_argument('-r', '--csr', help='CSR file (use existing CSR for enrollment)')
    parser.add_argument('-l', '--cert-out', default='client.crt', help='Output file for certificate')
    parser.add_argument('--cn', help='Common Name for certificate (if generating new)')
    parser.add_argument('--ca-id', help='CA Identifier (optional)')
    parser.add_argument('--org', help='Organization')
    parser.add_argument('--ou', help='Organizational Unit')
    parser.add_argument('--country', help='Country (2 letter code)')
    parser.add_argument('--state', help='State or Province')
    parser.add_argument('--locality', help='City or Locality')
    parser.add_argument('--key-size', type=int, default=2048, help='RSA key size (default: 2048)')
    parser.add_argument('--challenge', help='Challenge password')
    parser.add_argument('--key-out', default='client.key', help='Output file for private key (when generating)')
    parser.add_argument('--key-password', help='Password to encrypt/decrypt private key')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Disable SSL warnings for testing
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print("=" * 60)
    print("SCEP Client - Certificate Enrollment")
    print("=" * 60)
    
    # Create client
    client = SCEPClient(args.url, args.ca_id)
    
    # Step 1: Get CA capabilities
    print("\n[Step 1] Getting CA capabilities...")
    caps = client.get_ca_caps()
    
    # Step 2: Get CA certificate
    print("\n[Step 2] Getting CA certificate...")
    ca_cert = client.get_ca_cert()
    if not ca_cert:
        print("[-] Failed to get CA certificate. Exiting.")
        return 1
    
    # Step 3: Generate or load key and CSR
    print("\n[Step 3] Preparing key and CSR...")
    
    if args.csr and args.key:
        # Use existing key and CSR (sscep enroll mode)
        if not client.load_key(args.key, args.key_password):
            print("[-] Failed to load private key. Exiting.")
            return 1
        if not client.load_csr(args.csr):
            print("[-] Failed to load CSR. Exiting.")
            return 1
    elif args.cn:
        # Generate new key and CSR
        subject_attrs = {
            'organization': args.org,
            'organizational_unit': args.ou,
            'country': args.country,
            'state': args.state,
            'locality': args.locality,
        }
        client.generate_key_and_csr(args.cn, args.key_size, **subject_attrs)
    else:
        print("[-] Must provide either --cn (to generate) or both --key and --csr (to use existing)")
        return 1
    
    # Step 4: Send enrollment request
    print("\n[Step 4] Enrolling certificate...")
    cert = client.pkcs_req(args.challenge)
    
    # Step 5: Save results
    if cert:
        print("\n[Step 5] Saving results...")
        # Only save key if we generated it
        if not args.key:
            client.save_key(args.key_out, args.key_password)
        client.save_cert(cert, args.cert_out)
        
        print("\n" + "=" * 60)
        print("SUCCESS! Certificate enrolled successfully.")
        if not args.key:
            print(f"Private key: {args.key_out}")
        print(f"Certificate: {args.cert_out}")
        print("=" * 60)
        return 0
    else:
        print("\n" + "=" * 60)
        print("FAILED! Certificate enrollment failed.")
        print("=" * 60)
        return 1


if __name__ == '__main__':
    sys.exit(main())
