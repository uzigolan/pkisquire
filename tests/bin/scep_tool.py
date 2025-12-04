#!/usr/bin/env python3
"""
SCEP Tool - Python implementation similar to sscep
Supports: getca, enroll, getcrl, getcaps operations
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


class SCEPTool:
    def __init__(self, url, ca_identifier=None, verbose=False, debug=False):
        self.url = url.rstrip('/')
        self.ca_identifier = ca_identifier
        self.verbose = verbose
        self.debug = debug
        
    def log(self, message, level='info'):
        """Print log message based on verbosity"""
        if level == 'debug' and self.debug:
            print(f"DEBUG: {message}")
        elif level == 'verbose' and (self.verbose or self.debug):
            print(f"VERBOSE: {message}")
        elif level == 'info':
            print(message)
    
    def getca(self, output_file, fingerprint_algo='sha256'):
        """Get CA certificate(s) - equivalent to sscep getca"""
        url = f"{self.url}?operation=GetCACert"
        if self.ca_identifier:
            url += f"&message={self.ca_identifier}"
        
        self.log(f"Getting CA certificate from: {url}", 'verbose')
        
        try:
            response = requests.get(url, verify=False)
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                self.log(f"Response Content-Type: {content_type}", 'debug')
                
                # Parse certificate(s)
                certs = []
                if 'application/x-x509-ca-cert' in content_type:
                    # Single certificate
                    cert = x509.load_der_x509_certificate(response.content, default_backend())
                    certs.append(cert)
                    self.log(f"Received single CA certificate", 'verbose')
                elif 'application/x-x509-ca-ra-cert' in content_type or 'application/pkcs7' in content_type:
                    # PKCS#7 chain
                    try:
                        certs = pkcs7.load_der_pkcs7_certificates(response.content)
                        self.log(f"Received PKCS#7 certificate chain with {len(certs)} certificate(s)", 'verbose')
                    except:
                        # Try as single cert
                        cert = x509.load_der_x509_certificate(response.content, default_backend())
                        certs.append(cert)
                else:
                    # Unknown content type, try as DER cert
                    try:
                        cert = x509.load_der_x509_certificate(response.content, default_backend())
                        certs.append(cert)
                    except:
                        self.log(f"Could not parse certificate response", 'info')
                        return False
                
                # Write certificate(s) to file
                with open(output_file, 'wb') as f:
                    for cert in certs:
                        pem = cert.public_bytes(serialization.Encoding.PEM)
                        f.write(pem)
                
                self.log(f"Wrote {len(certs)} certificate(s) to: {output_file}", 'info')
                
                # Show fingerprint
                if certs:
                    for i, cert in enumerate(certs):
                        fingerprint = cert.fingerprint(getattr(hashes, fingerprint_algo.upper())())
                        fp_hex = ':'.join(f'{b:02x}' for b in fingerprint)
                        self.log(f"Certificate {i+1}: {cert.subject}", 'info')
                        self.log(f"  Fingerprint ({fingerprint_algo}): {fp_hex}", 'info')
                
                return True
            else:
                self.log(f"Failed to get CA certificate: HTTP {response.status_code}", 'info')
                return False
                
        except Exception as e:
            self.log(f"Error getting CA certificate: {e}", 'info')
            if self.debug:
                import traceback
                traceback.print_exc()
            return False
    
    def getcaps(self):
        """Get CA capabilities - equivalent to sscep getcaps"""
        url = f"{self.url}?operation=GetCACaps"
        if self.ca_identifier:
            url += f"&message={self.ca_identifier}"
        
        self.log(f"Getting CA capabilities from: {url}", 'verbose')
        
        try:
            response = requests.get(url, verify=False)
            
            if response.status_code == 200:
                caps = response.text.strip().split('\n')
                self.log("CA Capabilities:", 'info')
                for cap in caps:
                    if cap.strip():
                        print(f"  {cap.strip()}")
                return True
            else:
                self.log(f"Failed to get CA capabilities: HTTP {response.status_code}", 'info')
                return False
                
        except Exception as e:
            self.log(f"Error getting CA capabilities: {e}", 'info')
            return False
    
    def enroll(self, key_file, csr_file, ca_cert_file, output_file, 
               sig_key_file=None, sig_cert_file=None, key_password=None,
               max_poll_time=60, poll_interval=5, max_requests=10):
        """Enroll certificate - equivalent to sscep enroll"""
        
        # Load private key
        self.log(f"Loading private key from: {key_file}", 'verbose')
        try:
            with open(key_file, 'rb') as f:
                key_data = f.read()
            
            if key_password:
                private_key = serialization.load_pem_private_key(
                    key_data, password=key_password.encode(), backend=default_backend()
                )
            else:
                private_key = serialization.load_pem_private_key(
                    key_data, password=None, backend=default_backend()
                )
            self.log("Loaded private key", 'verbose')
        except Exception as e:
            self.log(f"Failed to load private key: {e}", 'info')
            return False
        
        # Load CSR
        self.log(f"Loading CSR from: {csr_file}", 'verbose')
        try:
            with open(csr_file, 'rb') as f:
                csr_data = f.read()
            csr = x509.load_pem_x509_csr(csr_data, default_backend())
            self.log(f"Loaded CSR for: {csr.subject}", 'verbose')
        except Exception as e:
            self.log(f"Failed to load CSR: {e}", 'info')
            return False
        
        # Load CA certificate (optional for validation)
        ca_cert = None
        if ca_cert_file:
            self.log(f"Loading CA certificate from: {ca_cert_file}", 'verbose')
            try:
                with open(ca_cert_file, 'rb') as f:
                    ca_cert_data = f.read()
                ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())
                self.log(f"Loaded CA certificate: {ca_cert.subject}", 'verbose')
            except Exception as e:
                self.log(f"Warning: Could not load CA certificate: {e}", 'verbose')
        
        # Send enrollment request
        self.log("Sending enrollment request...", 'info')
        
        # Create PKCS#7 request (simplified - real SCEP needs proper PKCS#7 wrapping)
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        
        # Encode as base64 for URL
        message = base64.b64encode(csr_der).decode('ascii')
        
        url = f"{self.url}?operation=PKIOperation&message={message}"
        self.log(f"POST to: {self.url}?operation=PKIOperation", 'debug')
        
        try:
            response = requests.post(url,
                                    data=csr_der,
                                    headers={'Content-Type': 'application/pkcs10'},
                                    verify=False)
            
            if response.status_code == 200:
                self.log("Enrollment request successful", 'verbose')
                
                # Try to parse certificate from response
                try:
                    # Response should be PKCS#7 with certificate
                    certs = pkcs7.load_der_pkcs7_certificates(response.content)
                    if certs:
                        cert = certs[0]
                        self.log(f"Received certificate: {cert.subject}", 'info')
                        
                        # Write certificate
                        pem = cert.public_bytes(serialization.Encoding.PEM)
                        with open(output_file, 'wb') as f:
                            f.write(pem)
                        
                        self.log(f"Wrote certificate to: {output_file}", 'info')
                        return True
                    else:
                        self.log("No certificate in response", 'info')
                        # Save raw response
                        with open(output_file, 'wb') as f:
                            f.write(response.content)
                        self.log(f"Wrote raw response to: {output_file}", 'info')
                        return True
                        
                except Exception as e:
                    self.log(f"Could not parse certificate: {e}", 'verbose')
                    # Try as single DER certificate
                    try:
                        cert = x509.load_der_x509_certificate(response.content, default_backend())
                        self.log(f"Received certificate: {cert.subject}", 'info')
                        
                        pem = cert.public_bytes(serialization.Encoding.PEM)
                        with open(output_file, 'wb') as f:
                            f.write(pem)
                        
                        self.log(f"Wrote certificate to: {output_file}", 'info')
                        return True
                    except:
                        # Save raw response
                        with open(output_file, 'wb') as f:
                            f.write(response.content)
                        self.log(f"Wrote raw response to: {output_file}", 'info')
                        return True
            else:
                self.log(f"Enrollment failed: HTTP {response.status_code}", 'info')
                self.log(f"Response: {response.text[:500]}", 'debug')
                return False
                
        except Exception as e:
            self.log(f"Error during enrollment: {e}", 'info')
            if self.debug:
                import traceback
                traceback.print_exc()
            return False
    
    def getcrl(self, key_file, cert_file, ca_cert_file, output_file, 
               serial_number=None, key_password=None):
        """Get CRL - equivalent to sscep getcrl"""
        
        # Load private key
        self.log(f"Loading private key from: {key_file}", 'verbose')
        try:
            with open(key_file, 'rb') as f:
                key_data = f.read()
            
            if key_password:
                private_key = serialization.load_pem_private_key(
                    key_data, password=key_password.encode(), backend=default_backend()
                )
            else:
                private_key = serialization.load_pem_private_key(
                    key_data, password=None, backend=default_backend()
                )
            self.log("Loaded private key", 'verbose')
        except Exception as e:
            self.log(f"Failed to load private key: {e}", 'info')
            return False
        
        # Load certificate
        self.log(f"Loading certificate from: {cert_file}", 'verbose')
        try:
            with open(cert_file, 'rb') as f:
                cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            self.log(f"Loaded certificate: {cert.subject}", 'verbose')
        except Exception as e:
            self.log(f"Failed to load certificate: {e}", 'info')
            return False
        
        # Send GetCRL request
        self.log("Requesting CRL...", 'info')
        
        url = f"{self.url}?operation=GetCRL"
        if self.ca_identifier:
            url += f"&message={self.ca_identifier}"
        
        self.log(f"GET from: {url}", 'debug')
        
        try:
            response = requests.get(url, verify=False)
            
            if response.status_code == 200:
                self.log("CRL request successful", 'verbose')
                
                # Write CRL
                with open(output_file, 'wb') as f:
                    f.write(response.content)
                
                self.log(f"Wrote CRL to: {output_file}", 'info')
                
                # Try to parse and show info
                try:
                    crl = x509.load_der_x509_crl(response.content, default_backend())
                    self.log(f"CRL Issuer: {crl.issuer}", 'info')
                    self.log(f"Last Update: {crl.last_update}", 'info')
                    self.log(f"Next Update: {crl.next_update}", 'info')
                    self.log(f"Revoked Certificates: {len(list(crl))}", 'info')
                except:
                    pass
                
                return True
            else:
                self.log(f"CRL request failed: HTTP {response.status_code}", 'info')
                return False
                
        except Exception as e:
            self.log(f"Error getting CRL: {e}", 'info')
            if self.debug:
                import traceback
                traceback.print_exc()
            return False


def main():
    parser = argparse.ArgumentParser(
        description='SCEP Tool - Python implementation',
        usage='%(prog)s OPERATION [OPTIONS]'
    )
    
    # Operation (positional)
    parser.add_argument('operation', 
                       choices=['getca', 'getnextca', 'enroll', 'getcert', 'getcrl', 'getcaps'],
                       help='SCEP operation to perform')
    
    # General options
    parser.add_argument('-u', '--url', required=True, 
                       help='SCEP server URL')
    parser.add_argument('-i', '--identifier',
                       help='CA identifier string')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('-d', '--debug', action='store_true',
                       help='Debug output')
    
    # Certificate/key files
    parser.add_argument('-c', '--ca-cert',
                       help='CA certificate file')
    parser.add_argument('-k', '--key',
                       help='Private key file')
    parser.add_argument('-r', '--request',
                       help='Certificate request file (CSR)')
    parser.add_argument('-l', '--local-cert',
                       help='Local certificate file')
    parser.add_argument('-w', '--write',
                       help='Write output to file')
    
    # Additional options
    parser.add_argument('-K', '--sig-key',
                       help='Signature private key file')
    parser.add_argument('-O', '--sig-cert',
                       help='Signature certificate file')
    parser.add_argument('-F', '--fingerprint',
                       default='sha256',
                       choices=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'],
                       help='Fingerprint algorithm')
    parser.add_argument('-s', '--serial',
                       help='Certificate serial number')
    parser.add_argument('-t', '--poll-interval', type=int, default=5,
                       help='Polling interval in seconds')
    parser.add_argument('-T', '--max-poll-time', type=int, default=60,
                       help='Max polling time in seconds')
    parser.add_argument('-n', '--max-requests', type=int, default=10,
                       help='Max number of requests')
    parser.add_argument('--key-password',
                       help='Private key password')
    
    args = parser.parse_args()
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Create tool instance
    tool = SCEPTool(args.url, args.identifier, args.verbose, args.debug)
    
    # Execute operation
    success = False
    
    if args.operation == 'getca':
        if not args.ca_cert:
            print("Error: -c/--ca-cert is required for getca operation")
            return 1
        success = tool.getca(args.ca_cert, args.fingerprint)
    
    elif args.operation == 'getcaps':
        success = tool.getcaps()
    
    elif args.operation == 'enroll':
        if not all([args.key, args.request, args.local_cert]):
            print("Error: -k/--key, -r/--request, and -l/--local-cert are required for enroll")
            return 1
        success = tool.enroll(
            args.key, args.request, args.ca_cert, args.local_cert,
            args.sig_key, args.sig_cert, args.key_password,
            args.max_poll_time, args.poll_interval, args.max_requests
        )
    
    elif args.operation == 'getcrl':
        if not all([args.key, args.local_cert, args.write]):
            print("Error: -k/--key, -l/--local-cert, and -w/--write are required for getcrl")
            return 1
        success = tool.getcrl(
            args.key, args.local_cert, args.ca_cert, args.write,
            args.serial, args.key_password
        )
    
    else:
        print(f"Operation '{args.operation}' not yet implemented")
        return 1
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
