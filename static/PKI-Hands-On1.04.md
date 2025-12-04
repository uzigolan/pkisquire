

## Company Confidential
This document contains information that is proprietary to RAD Data Communications Ltd. ("RAD"). No part of this document
may be reproduced or published or used in any form whatsoever without prior written approval by RAD Data Communications.
Right, title and interest, all information, copyrights, patents, know-how, trade secrets and other intellectual property or other
proprietary rights relating to this document and to the products described therein and any software components contained
therein are proprietary products of RAD protected under international copyright law and shall be and remain solely with RAD.
The trade names mentioned in this document are owned by RAD. No right, license, or interest to such trademark is granted
hereunder, and you agree that no such right, license, or interest shall be asserted by you with respect to such trademark. You
shall not copy, reverse, compile or reverse assemble all or any portion of this document or the product mentioned therein. You
are prohibited from, and shall not, directly or indirectly, develop, market, distribute, license, or sell any product that supports
substantially similar functionality to the product mentioned in this document, based on or derived in any way from such a
product. Your undertaking in this paragraph shall survive perpetually.
PKI Hands-On 1.04








Last updated 19-Nov-2025
Doc. version 1.04
Doc. owner Uzi Golan
Approved by
Customer R&D
Project or installation name
Project number
Solution name Choose an item.
RAD products and versions included
Content type
## Keywords



Error! No text of specified style in document.

19-Nov-2025  Page 2

## Contents
1 Introduction ................................................................................................................................ 4
1.1 Glossary ............................................................................................................................................ 4
1.2 PKI Concept....................................................................................................................................... 4
1.3 Overview ........................................................................................................................................... 6
Features ........................................................................................................................................... 6
Quantum safe keys .......................................................................................................................... 7
1.4 Purpose ............................................................................................................................................. 8
1.5 Scope ................................................................................................................................................ 8
2 PKI platform ................................................................................................................................ 9
2.1 Server OS requirements ................................................................................................................... 9
2.2 Installation ........................................................................................................................................ 9
Python .............................................................................................................................................. 9
Server ............................................................................................................................................. 10
Complementary ............................................................................................................................. 13
2.3 Generate Root and intermediate certification ............................................................................... 16
Generate Root Certificate .............................................................................................................. 17
Generating Intermediate (Sub) Certificate .................................................................................... 18
2.4 Configuration .................................................................................................................................. 21
2.5 Run Server ...................................................................................................................................... 23
Shell Command .............................................................................................................................. 23
OS Service ...................................................................................................................................... 23
2.6 Ports................................................................................................................................................ 25
2.7 Layout ............................................................................................................................................. 26
2.8 Keys Managment ............................................................................................................................ 27
2.9 Profiles Management ..................................................................................................................... 29
Profiles ........................................................................................................................................... 30
Templates ...................................................................................................................................... 32
2.10 Certificate actions ......................................................................................................................... 34
List .................................................................................................................................................. 35
View ............................................................................................................................................... 35
Download ....................................................................................................................................... 36
PFX ................................................................................................................................................. 36
Revoke ............................................................................................................................................ 37
Delete ............................................................................................................................................. 37
2.11 Certificate Requests ..................................................................................................................... 37
UI .................................................................................................................................................... 37
Linux ............................................................................................................................................... 39

Error! No text of specified style in document.

19-Nov-2025  Page 3

2.12 Validity Period .............................................................................................................................. 40
2.13 Server Certificate Extension ......................................................................................................... 40
2.14 Enrollment .................................................................................................................................... 42
UI signing ........................................................................................................................................ 42
EST .................................................................................................................................................. 43
SCEP (in development) ................................................................................................................... 44
2.15 Verification Authority (VA) ........................................................................................................... 45
View ............................................................................................................................................... 46
Download ....................................................................................................................................... 46
Inspect ............................................................................................................................................ 47
MQTTs with CRL file ....................................................................................................................... 47
2.16 CA certificate management .......................................................................................................... 49
Download ....................................................................................................................................... 49
View ............................................................................................................................................... 50
Update ........................................................................................................................................... 50
Generate ........................................................................................................................................ 50
2.17 Online Certificate Status Protocol (OCSP) .................................................................................... 53
Certificate based Servers using OCSP ............................................................................................ 54
2.18 Post-Quantum  Keys ..................................................................................................................... 55
2.19 APIs ............................................................................................................................................... 57
2.20 Inspect .......................................................................................................................................... 59
2.21 Config ............................................................................................................................................ 60
2.22 ChatPikachu .................................................................................................................................. 61
2.23 Help .............................................................................................................................................. 62
2.24 Logs ............................................................................................................................................... 63
Change History ................................................................................................................................ 64


Error! No text of specified style in document.

19-Nov-2025  Page 4

## 1 Introduction
## 1.1 Glossary

SCEP - SCEP (Simple Certificate Enrollment Protocol) enables automated certificate management by
allowing devices to securely request and retrieve certificates from a CA using HTTP-based
communication.
Quantum-Safe OpenSSL Provider - oqsprovider is an open source OpenSSL provider developed as part
of the Open Quantum Safe project.It integrates post quantum cryptographic algorithms into OpenSSL
3.x, enabling applications to generate and use quantum safe keys and operations seamlessly. This
provider offers implementations of various
MQTTs Broker - An MQTTs broker is a server that routes messages between clients using a
publish/subscribe model and TLS Certificate authentication and encapsulation method.
EST Enrollment method - EST enrollment technology automates certificate issuance by allowing devices
to submit CSRs and receive signed certificates over secure channels.
CRL - (Certificate Revocation List) is a mechanism for maintaining and distributing a list of digital
certificates that have been revoked by a Certificate Authority, ensuring that clients can verify certificate
validity.
Certificate Revoking - Certificate revoking is the process of invalidating a digital certificate before its
expiration, ensuring it can no longer be trusted.
OCSP - A real-time certificate status checking protocol that allows clients to verify whether a digital
certificate has been revoked, without downloading the full CRL. OCSP improves performance and
bandwidth usage compared to traditional revocation lists.


1.2 PKI Concept

Certification Authority (CA) part of Public Key Infrastructure (PKI) according to standards such as X.509
and IETF-PKIX
PKI Architecture


Error! No text of specified style in document.

19-Nov-2025  Page 5




From : https://docs.keyfactor.com/ejbca/9.0/ejbca-concepts

Root CA
A RootCA has a self-signed certificate and is also called Trusted Root. Verification of other certificates in
the PKI ends with the RootCAs self-signed certificate. Since the RootCAs certificate is self-signed it must
somehow be configured as a trusted root for all clients in the PKI.
Sub CA
A subordinate CA, or SubCA for short, is a CA whose certificate is signed by another CA, which can be
another SubCA or a RootCA. Since the SubCAs certificate is signed by another CA, it does not have to be
configured as a trusted root. It is part of a certificate chain that ends in the RootCA.
Registration Authority (RA)
A Registration Authority (RA) is an administrative function that registers entities in the PKI. The RA is
trusted to identify and authenticate entities according to the CAs policy. There can be one or more RAs
connected to each CA in the PKI.
Validation Authority (VA)

A Validation Authority (VA) is responsible for providing information on whether a certificate is currently
valid or not. The VA does not issue or revoke certificates, but it validates certificates by providing a list of
revoked certificates for a CA, known as a Certificate Revocation List (CRL). Another method that the VA
can support is the Online Certificate Status Protocol (OCSP). It is a real-time lookup of a certificate
status, compared to the CRL which is generated on a set schedule. The VA can respond to OCSP requests
and reply if a certificate is good, revoked, or unknown. There can be one or more VAs connected to each
CA in the PKI.


Error! No text of specified style in document.

19-Nov-2025  Page 6


## 1.3 Overview
This certificate management system offers an intuitive UI and endpoints to submit CSRs and manage
certificates—allowing users to view, download, revoke, and delete them. It also provides access to CA
chains, CRLs, and certificate statuses, while supporting advanced protocols like SCEP, EST, and OCSP for
comprehensive lifecycle management.
## Features
The platform supports the following features either UI or API methods

## CA
## General
## Download
CA Chain
curl -k  https://pikachu-ca.iot-
rad.com:5443/downloads/chain
Returns full CA
chain file

## Download
## CRL
curl -k  https://pikachu-ca.iot-
rad.com:4443/downloads/crl
Generates and
downloads latest
## Certificate
## Revocation List

## Certificate
## Status
curl -k  https://pikachu-ca.iot-
rad.com:4443/status/0xc75f573d9cb2b581
Returns status as
valid, revoked, or
not found in JSON

## Expired
## Certificates
curl -k  https://pikachu-ca.iot-rad.com:5443/expired Returns list of
certificate IDs that
are expired

## Download
## CSR
curl -k  https://pikachu-ca.iot-
rad.com:5443///requests/1/download
Serves saved CSR if
available
## SCEP

SCEP  CRL sscep getcrl  -d  -u http://pikachu-ca.iot-
rad.com:8090/scep   -c ca_rsa.crt  -w crl.pem -l local.crt
-k local.key


## SCEP
## Enrolment
sscep enroll -d -v  -u http://pikachu-ca.iot-
rad.com:8090/scep   -c rad_ca_sub_rsa.crt   -k
client1.key   -r client1.csr   -l client1.crt


## SCEP CA
## Certs
sscep getcap  -d  -u http://pikachu-ca.iot-
rad.com:8090/scep   -c cap.pem


Error! No text of specified style in document.

19-Nov-2025  Page 7

## EST EST
## Enrollment
curl -k -X POST --data-binary @etx.csr.der
https://openxpki.iot-rad.com:4443/.well-
known/est/simpleenroll   -H "Content-Type:
application/pkcs10"   --output etx.crt.p7
Accepts DER CSR
and returns signed
certificate in PKCS#7

## EST CA
## Certs
curl -k  https://pikachu-ca.iot-rad.com:4443/.well-
known/est/cacerts --output chain.crt
Returns CA chain in
PKCS#7 format
## OCSP OCSP
## Responder
openssl ocsp -reqout ocsp_request.der  -issuer
rad_ca_sub.crt  -cert valid.crt -url https://pikachu-ca.iot-
rad.com:4443/ocsp -resp_text -respout
ocsp_response.der
Returns OCSP status
for a given
certificate in DER
format
## CA
## General
## Download
CA Chain
curl -k  https://pikachu-ca.iot-
rad.com:5443/downloads/chain
Returns full CA
chain file

## Download
## CRL
curl -k  https://pikachu-ca.iot-
rad.com:4443/downloads/crl
Generates and
downloads latest
## Certificate
## Revocation List

## Certificate
## Status
curl -k  https://pikachu-ca.iot-
rad.com:4443/status/0xc75f573d9cb2b581
Returns status as
valid, revoked, or
not found in JSON

## Expired
## Certificates
curl -k  https://pikachu-ca.iot-rad.com:5443/expired Returns list of
certificate IDs that
are expired

## Download
## CSR
curl -k  https://pikachu-ca.iot-
rad.com:5443///requests/1/download
Serves saved CSR if
available

Quantum safe keys

Quantum safe keys are encryption keys generated using algorithms that resist attempts by quantum
computers, helping secure data against emerging quantum threats.
For instance,
- mldsa44 – which corresponds to NIST Level 1 (Dilithium2)
- mldsa65 – corresponding roughly to Dilithium3 (NIST Level 3)

Error! No text of specified style in document.

19-Nov-2025  Page 8

- mldsa87 – corresponding roughly to Dilithium5 (NIST Level 5)

## 1.4 Purpose
The purpose of this platform is to provide a robust PKI solution that securely provisions and manages
RAD devices and servers—such as those operating with MQTT—by seamlessly integrating with CA
servers.
## 1.5 Scope
in non-production environments, with a strong emphasis on tenant isolation, robust security measures,
and high availability.

Error! No text of specified style in document.

19-Nov-2025  Page 9

2 PKI platform
The Lifecycle maintenance ansible playbook contains files and ansible playbooks. Once installed the user
can perform the maintenance operations.

2.1 Server OS requirements

## Operating System  Version

## Rocky    9.x

## 2.2 Installation
## Python
Install python 3 and complimentary packages
sudo dnf install -y epel-release

#sudo dnf module enable -y python3.11

sudo dnf install -y python3.11 python3.11-devel python3.11-pip git

sudo dnf groupinstall -y "Development Tools"


sudo alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 100
sudo alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.11 100

pip3 install flask cryptography oscrypto asn1crypto flask_sqlalchemy

allow python39 programs to use privileged ports (below 1024)

Error! No text of specified style in document.

19-Nov-2025  Page 10


sudo setcap 'cap_net_bind_service=+ep' /usr/bin/python3.11


## Server
Extract the pki_server_102.tar.gz
tar xvfz pki_server_102.tar.gz
cd pki-server-2

it will open the following directories and files


Error! No text of specified style in document.

19-Nov-2025  Page 11


├── app.log
├── app.py
├── asn1.py
├── builders.py
├── ca_mode.conf
├── ca.py
├── certificates
├── certs.db
├── chain.crt
├── chainx.crt
├── config_bp.py
├── config.ini
├── config_storage.py
├── db
│   └── certs.db
├── dbtypes.py
├── dummy.key
├── dumps
├── enums.py
├── envelope.py
├── est_cert_chain.p7
├── est_chain.p7
├── est_signed_cert.pem
├── extensions.py
## ├── FETCH_HEAD
├── html_templates
│   ├── api.html
│   ├── app.log
│   ├── ca.html
## │   ├── _certificate_detail.html
│   ├── config.html
│   ├── edit_profile.html
│   ├── generate_csr.html
│   ├── generate_key.html
│   ├── index.html
│   ├── inspect.html
│   ├── layout.html
│   ├── list_certificates.html
│   ├── list_certificates.html.171125
│   ├── list_certificates.html.delete
│   ├── list_csrs.html
│   ├── list_keys.html
│   ├── list_profiles.html
│   ├── list_rendered.html
│   ├── list_templates.html
│   ├── logs.html
│   ├── profile_file.html
│   ├── profile_result.html
│   ├── rendered_file.html
│   ├── rendered_template.html
│   ├── server_ext.html
│   ├── sign.html
│   ├── template_form.html
│   ├── va.html

Error! No text of specified style in document.

19-Nov-2025  Page 12

│   ├── view_csr.html
│   ├── view.html
│   └── view_key.html
├── logs
│   ├── server.log
│   └── server.log.1
├── pki-https
│   ├── pikachu_issued_https.crt
│   ├── pikachu_issued_https.key
│   ├── tls.cert.pem
│   └── tls.key.pem
├── pki-misc
│   ├── crl.pem
│   ├── server_ext.cnf
│   └── validity.conf
├── pki-root
│   └── rad_ca_root.crt
├── pki-server-2.code-workspace
├── pki-subca
│   ├── rad_ca_sub_ec.crt
│   ├── rad_ca_sub_ec.key
│   ├── rad_ca_sub_rsa.crt
│   ├── rad_ca_sub_rsa.key
│   ├── rad_chain_ec.crt
│   └── rad_chain_rsa.crt
## ├── __pycache__
├── README.md
├── static
│   ├── favicon-16x16.png
│   ├── favicon-32x32.png
│   ├── help.pdf -> PKI-Hands-On1.03.pdf
│   ├── PKI-Hands-On1.02.pdf
│   └── PKI-Hands-On1.03.pdf
├── version.txt
├── x509_keys.py
├── x509_profiles
## │   ├── 6w_ca_root_2.cnf
## │   ├── 6w_ca_root_2x.cnf
## │   ├── 6w_ca_root.cnf
## │   ├── 6w_ca_root_x.cnf
│   ├── bitbucket_server.cnf
├── x509_profiles.py
├── x509_requests.py
└── x509_templates
## ├── 6w_ca_root_2.cnf.j2
## ├── 6w_ca_root.cnf.j2
## ├── 6w_ca_root_ext.cnf.j2
## ├── 6w_ca_sub.cnf.j2
├── crl_ocsp_ext_alt.cnf.j2
├── crl_ocsp_ext.cnf.j2
├── eon_server_ext.cnf.j2


Error! No text of specified style in document.

19-Nov-2025  Page 13

## Complementary
Following installation of commands and libraries essential for testing and using the server
## SSCEP
Rocky 9 lack OS repository installation there for it needed to be complied, linked and installed

git clone https://github.com/zhaozg/openscep.git
cd openscep
chmod u+x configure
## ./configure

make

sudo make install
Note : If missing libraries install using  the OS dnf
EST-Client

From repo https://github.com/globalsign/est
sudo dnf install -y golang

git clone https://github.com/globalsign/est.git

go install github.com/globalsign/est/cmd/estclient@latest

sudo cp go/bin/estclient   /usr/local/bin/estclient



Error! No text of specified style in document.

19-Nov-2025  Page 14

## Quantum Safe Algorithm
Quantum safe algorithms successful installation requires openssl 3.x and other development packages
Prerequisite installation of Ninja
sudo dnf config-manager --set-enabled crb
sudo dnf install -y epel-release
sudo dnf install -y ninja-build

sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y cmake ninja-build git openssl-devel libffi-devel

install quantum resistant algorithms (like Dilithium, Falcon, Kyber, and SPHINCS+)
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
## ./scripts/fullbuild.sh
sudo cmake --install _build
find the openssl.cnf file  and add it manually
ls -l /etc/ssl/openssl.cnf
lrwxrwxrwx. 1 root root 24 Aug 21  2024 /etc/ssl/openssl.cnf ->
## /etc/pki/tls/openssl.cnf

# add the new provider

sudo vi /etc/pki/tls/openssl.cnf

## [provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect
## [default_sect]
activate = 1
## [oqsprovider_sect]
activate = 1

test the openssl
#run command
openssl list -providers
## #output
## Providers:
default
name: OpenSSL Default Provider
version: 3.2.2
status: active
oqsprovider

Error! No text of specified style in document.

19-Nov-2025  Page 15

name: OpenSSL OQS Provider
version: 0.8.1-dev
status: active
we can see that oqsprovider provider is active

MQTTs broker

Using distribution mosquitto  with docker compose

mkdir mqtt
cd mqtt


cat > docker-compose.yml <<EOL


version: '3'
services:
mosquitto:
image: eclipse-mosquitto:latest
container_name: mosquitto
network_mode: "host"  # Use host network mode
ports:
- "1883:1883"    # Default MQTT
- "2883:2883"    # Secure MQTT with TLS
- "9001:9001"    # WebSocket (if needed)
volumes:
## - ./mosquitto.conf:/mosquitto/config/mosquitto.conf
## - ./mosquitto/certs:/mosquitto/certs
restart: unless-stopped
## EOL
make configuration file
cat > mosquitto.conf <<EOL

per_listener_settings true

listener 1883 0.0.0.0
allow_anonymous true
log_type all

listener 2883 0.0.0.0
cafile /mosquitto/certs/CA.cert
certfile /mosquitto/certs/est_mqtt_server_1.pem

Error! No text of specified style in document.

19-Nov-2025  Page 16

keyfile /mosquitto/certs/est_mqtt_server_1.key

crlfile /mosquitto/certs/crl.pem

require_certificate true
use_identity_as_username true
log_type all
## EOL

populate certification directory
mkdir certs
cd certs

with files
est_mqtt_server_1.pem
est_mqtt_server_1.key
crl_client_2.pem
CA.cert


By executing the following command Server is up and running
cd pki-srever-2
python app.py
all logs are written to the stdout and file output.log



2.3 Generate Root and intermediate certification

Every CA server is based on Root certificate and one or more intermediate (sub) certificates

Following procedure on how to generate a root and intermediate certificates for the CA server

Error! No text of specified style in document.

19-Nov-2025  Page 17

## Generate Root Certificate
Create root EC key

openssl ecparam -name prime256v1 -genkey -noout -out rad_ca_root.key
Prepare certificate configuration file

cat > rad_ca_root.cnf <<EOL
# CA Certificate Configuration Template for Root ECC Certificates
[ req ]
default_bits       = 4096
default_md         = sha256
prompt             = no
distinguished_name = dn
x509_extensions    = v3_ca

[ dn ]
## C  = IL
## ST = TLV
## L  = Tel Aviv
## O  = RAD
## OU = RD
CN = RAD Test ECDSA

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:1
## EOL
Self-sign root certificate

openssl req -config rad_ca_root.cnf -key rad_ca_root.key -new -x509 -days
3650 -sha256 -out rad_ca_root.crt
Prepare signing server extension configuration file

cat > ca_root_ext.cnf <<EOL
[ v3_intermediate ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = keyCertSign, cRLSign
crlDistributionPoints  = URI:https://pikachu-ca.rnd-rad.com/downloads/crl
## EOL


Error! No text of specified style in document.

19-Nov-2025  Page 18

Generating Intermediate (Sub) Certificate
EC based Key Certificate
Create sub key

openssl ecparam -name prime256v1 -genkey -noout -out rad_ca_sub_ec.key
Prepare certificate configuration file

cat > rad_ca_sub_ec.cnf<<EOL
[ req ]
default_bits       = 2048
default_md         = sha256
prompt             = no
distinguished_name = dn
req_extensions     = v3_intermediate
[ dn ]
## C  = IL
## ST = TLV
## L  = Tel Aviv
## O  = RAD
## OU = RD
CN = RADSubTestECDSA
[ v3_intermediate ]
subjectKeyIdentifier   = hash
#authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = keyCertSign, cRLSign
## EOL
Generate Certificate request

openssl req -new -config rad_ca_sub_ec.cnf  -key rad_ca_sub_ec.key -out
rad_ca_sub_ec.csr
Sign certificate

openssl x509 -req -in rad_ca_sub_ec.csr -CA rad_ca_root.crt -CAkey
rad_ca_root.key -CAcreateserial -out rad_ca_sub_ec.crt -days 3650 -sha256 -
extfile ca_root_ext.cnf -extensions v3_intermediate



Error! No text of specified style in document.

19-Nov-2025  Page 19

RSA based Key Certificate
Create sub key

openssl genpkey -algorithm RSA -out rad_ca_sub_rsa.key -pkeyopt
rsa_keygen_bits:4096
Prepare certificate configuration file

cat > rad_ca_sub_rsa.cnf<<EOL
[ req ]
default_bits       = 4096
default_md         = sha256
prompt             = no
distinguished_name = dn
req_extensions     = v3_intermediate
[ dn ]
## C  = IL
## ST = TLV
## L  = Tel Aviv
## O  = RAD
## OU = RD
CN = RADSubTestECDSA
[ v3_intermediate ]
subjectKeyIdentifier   = hash
#authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = keyCertSign, cRLSign
## EOL
Generate certificate request

openssl req -new -config rad_ca_sub_rsa.cnf  -key rad_ca_sub_rsa.key -out
rad_ca_sub_rsa.csr

Sign certificate

openssl x509 -req -in rad_ca_sub_rsa.csr -CA rad_ca_root.crt -CAkey
rad_ca_root.key -CAcreateserial -out rad_ca_sub_rsa.crt -days 3650 -sha256 -
extfile ca_root_ext.cnf -extensions v3_intermediate


Error! No text of specified style in document.

19-Nov-2025  Page 20

Copy keys Certificates
The Certificates and Keys must be located according to the attributes in the CA server configuration file
## (config.ini)
PROJ_DIR=~/pki-server-2
Cp rad_ca_root.key rad_ca_root.crt $PROJ_DIR/pki-root/
cp rad_ca_sub_ec.crt rad_ca_sub_rsa.crt rad_ca_sub_ec.key rad_ca_sub_rsa.key
$PROJ_DIR/pki-subca

cd $PROJ_DIR

cat pki-subca/rad_ca_sub_ec.crt pki-root/rad_ca_root.crt > pki-subca/rad_chain_ec.crt
cat pki-subca/rad_ca_sub_rsa.crt pki-root/rad_ca_root.crt > pki-
subca/rad_chain_rsa.crtv



















Error! No text of specified style in document.

19-Nov-2025  Page 21

## 2.4 Configuration
The server is configured by config.ini file , secret protected

Error! No text of specified style in document.

19-Nov-2025  Page 22

## [DEFAULT]
# general Flask settings
## SECRET_KEY = *******

## [CA]
# Which subordinate CA to use by default: "EC" or "RSA"
mode = EC

# Paths for both modes; the get_ca_config() helper below will pick the right
SUBCA_KEY_PATH_EC    = pki-subca/rad_ca_sub_ec.key
SUBCA_CERT_PATH_EC   = pki-subca/rad_ca_sub_ec.crt
CHAIN_FILE_PATH_EC   = pki-subca/rad_chain_ec.crt

SUBCA_KEY_PATH_RSA   = pki-subca/rad_ca_sub_rsa.key
SUBCA_CERT_PATH_RSA  = pki-subca/rad_ca_sub_rsa.crt
CHAIN_FILE_PATH_RSA  = pki-subca/rad_chain_rsa.crt

ROOT_CERT_PATH       = pki-root/rad_ca_root.crt

## [SCEP]
# enable or disable SCEP entirely
enabled = true

# optional path to a file where we persist the serial across restarts
serial_file = pki-subca/serial.txt

# Dump directory for raw SCEP requests (optional)
dump_dir = pki-subca/dumps

# HTTP port for unauthenticated SCEP
http_port = 8090

## [HTTPS]
# HTTPS certificate & key for your main CA UI
ssl_cert = pki-https/tls.cert.pem
ssl_key  = pki-https/tls.key.pem
port     = 443

## [TRUSTED_HTTPS]
# HTTPS certificate & key for your main CA UI
trusted_ssl_cert = pki-https/pikachu_issued_https.crt
trusted_ssl_key  = pki-https/pikachu_issued_https.key
trusted_port     = 4443

## [PATHS]
# everything else that was hard-coded
crl_path       = pki-misc/crl.pem
server_ext_cfg = pki-misc/server_ext.cnf
validity_conf  = pki-misc/validity.conf
db_path        = db/certs.db



Error! No text of specified style in document.

19-Nov-2025  Page 23

## 2.5 Run Server
## Shell Command
By executing the following command Server is up and running
cd pki-srever-2
nohup python app.py > app.log 2>&1 &

all logs are written to the stdout and file output.log
OS Service
Create the main service: pikachu-ca.service

sudo tee /etc/systemd/system/pikachu-ca.service > /dev/null << 'EOF'
[Unit]
Description=Pikachu CA Python App
## After=network-online.target
## Wants=network-online.target

[Service]
## Type=simple
## User=rocky
## Group=rocky
WorkingDirectory=/home/rocky/pki-server-2
ExecStart=/usr/bin/python3.11 /home/rocky/pki-server-2/app.py
## Restart=always
RestartSec=5s
Environment=PYTHONUNBUFFERED=1

# Allow binding to ports <1024
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
## EOF



Error! No text of specified style in document.

19-Nov-2025  Page 24


Create the healthcheck service: pikachu-ca-healthcheck.service


sudo tee /etc/systemd/system/pikachu-ca-healthcheck.service > /dev/null <<
## 'EOF'
[Unit]
Description=Healthcheck for pikachu-ca (restart if https://localhost fails)
## After=pikachu-ca.service

[Service]
## Type=oneshot
ExecStart=/usr/bin/bash -c '/usr/bin/curl -ksf --max-time 5
https://localhost/ || /usr/bin/systemctl restart pikachu-ca.service'
## EOF


Create the healthcheck timer: pikachu-ca-healthcheck.timer


sudo tee /etc/systemd/system/pikachu-ca-healthcheck.timer > /dev/null <<
## 'EOF'
[Unit]
Description=Periodic healthcheck for pikachu-ca

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
## Unit=pikachu-ca-healthcheck.service

[Install]
WantedBy=timers.target
## EOF


Reload systemd to pick up the new units

sudo systemctl daemon-reload


Enable services & timer at boot

Error! No text of specified style in document.

19-Nov-2025  Page 25


sudo systemctl enable pikachu-ca.service
sudo systemctl enable pikachu-ca-healthcheck.timer

Start everything now

sudo systemctl start pikachu-ca.service
sudo systemctl start pikachu-ca-healthcheck.timer


Check status / logs

# Main service status
sudo systemctl status pikachu-ca.service

# Timer and healthcheck
sudo systemctl status pikachu-ca-healthcheck.timer
sudo systemctl status pikachu-ca-healthcheck.service

# See timers
systemctl list-timers | grep pikachu

## # Logs
journalctl -u pikachu-ca.service -f
journalctl -u pikachu-ca-healthcheck.service -f




server can be access using the URL https://pikachu-ca.iot-rad.com:4443
## 2.6 Ports

The application as development tool can be used in the following ways

## Capability Configuration  Support
## Technology
## Description

Error! No text of specified style in document.

19-Nov-2025  Page 26

HTTPS without client
certificate
## [HTTPS]
## Port = 443
All One-way TLS
Server-authenticated TLS
Standard HTTPS
HTTPS that requires
client certificates
## [TRUSTED_HTTPS]
trusted_port     =
## 4443

All Mutual TLS (mTLS)
Two-way TLS
TLS with client authentication
## HTTP ( OCSP ) [DEFAULT]
http_port = 80

OCSP For older technologies
## HTTP ( SCEP )  [SCEP]
http_port = 8090



## 2.7 Layout
## Navigate Tiles

Certs - list certificates (Main view)
RA (sign) – Sign certificate
CSR Requests – create, delete, view and list certificates requests
Keys - create, delete, download view and list of keys
Profiles - create, edit, delete, view and list of profiles
VA (crl) – list revoked certificates and updated CRL
Server Ext – view edit and load profile to Extension configuration
CA(mode) – show the root and sub/intermediate certificates details

Error! No text of specified style in document.

19-Nov-2025  Page 27

Templates - Create Profile based on Templates
APIs – list of all APIs download CRL, CA certificate. Enrolments techniques Manual, SCEP and EST, and RA
## OCSP.
Inspect – Inspect PEM block or Base64‑encoded DER data
Config – show content of server config.ini file
hatPikachu – ChatGPT GPT for the server
Help – open new browser tab with help Pdf file
Logs – show the server log data
## Version – 1.0.4


## 2.8 Keys Managment
At the main view under management Links select Keys
Redirected to view with list of Keys


https://openxpki.iot-rad.com:4443/keys
to generate new key press button Generate New Key
Redirected to Generate a New Key

Error! No text of specified style in document.

19-Nov-2025  Page 28


Users can use either RSA, EC (elastic curve) and PQC (post-quantum) Key Type
RSA contains key sizes 2048,3072 and 4096
EC has curves prime256v1(secp256r1), secp384r1, secp521r1 and secp256k1
PQC has algorithms mldsa44 (Dilithium2 / NIST L1), mldsa65 (Dilithium3 / NIST L3) and mlds87
(Dilithium5 / NIST L5)
Add a key name and press button generate Key
The view will be redirected to List of Keys view
Press View at the key you wish to see details

Error! No text of specified style in document.

19-Nov-2025  Page 29


User can copy the Private and Public key data for any purpose

## 2.9  Profiles Management
The profile is used for various purposes
- Certificate configuration to generate CSRs
- CA server extension configuration to sing a CSR


Error! No text of specified style in document.

19-Nov-2025  Page 30

The profile can be created either by editing or rendered from template
## Profiles

View List of Profile Files contains all profiles able to view, create, edit or delete


https://openxpki.iot-rad.com/profiles/

to create new profiles, use Generate New Profile Action

Error! No text of specified style in document.

19-Nov-2025  Page 31



to edit profile, use the Edit Action



Error! No text of specified style in document.

19-Nov-2025  Page 32


## Templates
Templates added manually to the server under folder x509_templates
Template is jinja j2 style template for example

# CA Certificate Configuration Template for Root ECC Certificates
[ req ]
# Note: For ECC keys the “default_bits” option is not used.
default_md         = sha256
default_days       = 3650
prompt             = no
distinguished_name = dn
x509_extensions    = v3_ca
default_ec_curve   = prime256v1

[ dn ]
C  = {{ ca_country | default("FR") }}
ST = {{ ca_state | default("Ile-de-France") }}
L  = {{ ca_city | default("Paris") }}
O  = {{ ca_organization | default("6WIND") }}
OU = {{ ca_organizational_unit | default("CA Division") }}
CN = {{ ca_common_name | default("6WIND Test ECDSA RCA") }}

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, keyCertSign, cRLSign

At the main view under management Links select Templates
Redirected to view Select an X509 Template

https://openxpki.iot-rad.com:4443/x509_templates/

Error! No text of specified style in document.

19-Nov-2025  Page 33

Choose template and Load template by pressing Load Template button
The view will be redirected to Fill in Variables for Template


Change the defaults value to any you wish



Press Render profile to create a profile
The view will be redirected to Profile File with generate profile details

Error! No text of specified style in document.

19-Nov-2025  Page 34


A file with the name that has been given created at folder x509_profiles
Users can either press either the “Back to Template List” button or “View All Profiles Files” one
2.10 Certificate actions
Once certificate has been signed and issued the user can perform the following actions
- View – Display the certificate’s details and metadata.
- Download – Retrieve the certificate file for local use or storage.
- PFX – Generate and download a PFX/PKCS#12 bundle containing the certificate and private key.
- Revoke – Mark the certificate as invalid so it can no longer be trusted or used.
- Delete – Permanently remove the certificate record from the system.


Error! No text of specified style in document.

19-Nov-2025  Page 35


The Actions Delete, revoke and PFX are secret protected
Note: Users can also view the Root and intermediate (Sub) Certificate
## List
All certificates are contained in the Issued Certificates Table

The table can be filtered by either part of Common Name, Serial values, Key and Date
## View

Pressing the View Action open new page  (pressing back to home return to the main view)
## Change

Error! No text of specified style in document.

19-Nov-2025  Page 36



## Download
Pressing the Download Action, download a file containing
## 1. Required Certificate
- Intermediate issuer certificate (sub-CA)
- Root CA certificate

## PFX


Error! No text of specified style in document.

19-Nov-2025  Page 37

Download PFX/PKCS#12 bundle secret protected file contains the private key, certificate and
intermediate ( sub) CA certificate

Can be used to load to windows certification manager
## Revoke
Certificate revoking is the process of invalidating a digital certificate before its expiration, ensuring it can
no longer be trusted.
Pressing the Revoke Action revoking the certificate and later on adding it to the CRL  list

## Delete
Pressing the Delete Action, Certificate is deleted from DB and form the table

## 2.11 Certificate Requests
## UI
At the main view under management Links select CSR Requests
Redirected to view with list of certificate requests (CSR)


Error! No text of specified style in document.

19-Nov-2025  Page 38


https://openxpki.iot-rad.com/requests
to generate new CSR press button Generate New CSR
Redirected to Generate a New CSR

In order to make ne CSR select key from list , enter a Name and select a profile

https://openxpki.iot-rad.com:4443/requests/generate
press button Generate CSR to generate new one
The view will be redirected to CSR list
Press View at the CSR you wish to see details

Error! No text of specified style in document.

19-Nov-2025  Page 39



User can copy the PEM certificate and use for any purpose
## Linux

## Generate Key
openssl genrsa -out client1.key 2048

Generate request

prepare configuration to be added to the certificate request
for instance,

Error! No text of specified style in document.

19-Nov-2025  Page 40

cat > client1.cnf <<EOL
[ req ]
default_bits       = 2048
default_md         = sha256
distinguished_name = req_distinguished_name
attributes         = req_attrs
prompt             = no

[ req_distinguished_name ]
CN                 = client1.example.com
## O                  = My Organization
## C                  = US

[ req_attrs ]
challengePassword  = SecretChallenge
## EOL

Make the request
openssl req -new -key client1.key -config client1.cnf -out client1.csr

this request can be used for either UI signing or API based SCEP  or EST

## 2.12 Validity Period
User enrolls Certificate using Validity period (days)

Update using “Update Validity” button
## 2.13 Server Certificate Extension


Error! No text of specified style in document.

19-Nov-2025  Page 41

Users generate a CSR with custom attributes, but the server may omit, modify, or add attributes before
generating the key.

## Examples:
- Adding AIA for OCSP
- Adding URL for CRL retiring
- Adding URL for CA chain certificate retiring
- Omit suggested password given by the used for the enrolment but not needed anymore

Main View contains read only information of the current Server Extension configuration


To Edit the Server extension configuration, press the link “Manage Server Extensions” in a new view Edit
and using Save button save the configuration


Error! No text of specified style in document.

19-Nov-2025  Page 42


Using link Back To Home return to main view

## Notes :
- only authorityInfoAccess (AIA) and subjectAltName (SAN) supported .

## 2.14 Enrollment

UI signing
Using the web browser under Submit a CSR past the certificate request content and press Sign CSR
button
Users can load existing CSR from the list of Pending CSR Request




Error! No text of specified style in document.

19-Nov-2025  Page 43


After signing   the certificate will appear in the issued certificates table below


The table can be filtered by either part of Common Name or Serial values
## EST
EST enrollment technology automates certificate issuance by allowing devices to submit CSRs and
receive signed certificates over secure channels.

Convert the certificate request
openssl req -outform DER -in client1.csr -out client1.csr.der

send the enrolment command using curl

curl -k -X POST --data-binary @client1.csr.der \
https://openxpki.iot-rad.com:4443/.well-known/est/simpleenroll \
-H "Content-Type: application/pkcs10" \
--output client1.crt.p7


Error! No text of specified style in document.

19-Nov-2025  Page 44

Extract the certificate

openssl pkcs7 -inform DER -in client1.crt.p7 -print_certs -out client1.crt

the certificate added to the UI issues certificates table
tested issued certificate using openssl
openssl x509 -in client1.crt  -noout -text

enroll using command estclient

estclient enroll -server pikachu-ca.iot-rad.com:4443 -insecure -csr etx.csr -
out etx.crt
SCEP (in development)

For SCEP you must provide the CA of either full chain (Root + Sub CA) or only the intimidate one (Sub CA)
send the enrolment command using sscep command (see Complementary section for installing it)

sscep enroll -u http://openxpki.iot-rad.com:8090/scep \
-c ca.cert.pem \
-k client1.key \
-r client1.csr \
-l client1.crt

Note: to debug sscep command add -d option

the certificate added to the UI issues certificates table
tested issued certificate using openssl

Error! No text of specified style in document.

19-Nov-2025  Page 45

openssl x509 -in client1.crt  -noout -text


Convert the certificate request
openssl req -outform DER -in client1.csr -out client1.csr.der

send the enrolment command using curl

curl -k -X POST --data-binary @client1.csr.der \
https://openxpki.iot-rad.com:4443/.well-known/est/simpleenroll \
-H "Content-Type: application/pkcs10" \
--output client1.crt.p7

Extract the certificate

openssl pkcs7 -inform DER -in client1.crt.p7 -print_certs -out client1.crt

the certificate added to the UI issues certificates table
tested issued certificate using openssl
openssl x509 -in client1.crt  -noout -text

Note: based on GitHub repo https://github.com/mosen/SCEPy

2.15 Verification Authority (VA)
CRL (Certificate Revocation List) is a mechanism for maintaining and distributing a list of digital
certificates that have been revoked by a Certificate Authority, ensuring that clients can verify certificate
validity.

Error! No text of specified style in document.

19-Nov-2025  Page 46

## View

List of revoked certificates


## Download

Download the CRL by two methods:
- Using UI pressing the link Download CRL
- Using API endpoint

curl -k https://openxpki.iot-rad.com:4443/downloads/crl --output crl.pem


Error! No text of specified style in document.

19-Nov-2025  Page 47

## Inspect

Openssl based info.



MQTTs with CRL file


Error! No text of specified style in document.

19-Nov-2025  Page 48

Common Server using the CRL file to deny access of client with revoked certification is MQTT broker
mosquitto.

MQTT added configuration in mosquitto.conf (see Paragraph 2.2 Insulation  / complementary /MQTT
## Broker
crlfile /mosquitto/certs/crl_client_2.pem

the MQTT server deny revoked certificates-based connection attempts
The server must be periodically updated with new updated CRL

example adding crl updater to the docker compose

crl-updater:
image: alpine:latest
container_name: crl_updater
volumes:
## - ./mosquitto/certs:/mosquitto/
- /var/run/docker.sock:/var/run/docker.sock  # So we can signal the
mosquitto container
# Install curl and bash, then run a loop:
command: >
sh -c "apk add --no-cache curl bash &&
while true; do
echo 'Downloading new CRL file...';
curl -k https://openxpki.iot-rad.com:4443/downloads/crl --output
## /mosquitto/certs/crl.pem;
echo 'Triggering Mosquitto to reload its configuration...';
docker kill --signal=SIGHUP mosquitto;
echo 'Sleeping for 24 hours before next update...';
sleep 86400;
done"
restart: unless-stopped

Note: not tested yet


Error! No text of specified style in document.

19-Nov-2025  Page 49

2.16 CA certificate management
User can retrieve the following CA certificate
Root CA Certificate:
A trusted self-signed certificate that sits at the top of the certificate hierarchy. It is the anchor of trust
used to verify all other certificates in the chain.
Sub CA (Intermediate) Certificate:
A certificate issued by the Root CA (or another intermediate) to delegate signing authority. It acts as a
bridge between the Root CA and end-entity (leaf) certificates, improving security and scalability.

## Download

Download the CA Chain Certificate by two methods:
- Using UI pressing the link Download the CA Chain Cert

- Using API endpoint

curl -k https://openxpki.iot-rad.com:4443/downloads/chain --output
ca.chain.pem

the ca.chain.pem file can be inspected using openssl
openssl x509 -in ca.chain.pem -noout -text


Error! No text of specified style in document.

19-Nov-2025  Page 50

## View

Pressing the buttons “View Root CA Certificate” and “View Sub CA Certificate” redirect to to view page
with all needed Data
## Update
Change the configuration file config.ini

## [CA]
# Which subordinate CA to use by default: "EC" or "RSA"
mode = EC

# Paths for both modes; the get_ca_config() helper below will pick the right
SUBCA_KEY_PATH_EC    = /home/rocky/pki-subca/rad_ca_sub_ec.key
SUBCA_CERT_PATH_EC   = /home/rocky/pki-subca/rad_ca_sub_ec.crt
CHAIN_FILE_PATH_EC   = /home/rocky/pki-subca/rad_chain_ec.crt

SUBCA_KEY_PATH_RSA   = /home/rocky/pki-subca/rad_ca_sub_rsa.key
SUBCA_CERT_PATH_RSA  = /home/rocky/pki-subca/rad_ca_sub_rsa.crt
CHAIN_FILE_PATH_RSA  = /home/rocky/pki-subca/rad_chain_rsa.crt

ROOT_CERT_PATH       = /home/rocky/pki-root/rad_ca_root.crt
## [HTTPS]
# HTTPS certificate & key for your main CA UI
ssl_cert = /home/rocky/pki-https/tls.cert.pem
ssl_key  = /home/rocky/pki-https/tls.key.pem
port     = 4443
## Generate
Below example how to generate all needed CA files
Root CA
Generate Key using type EC and curve prime256v1(secp256r1)
Use root CA request configuration

Error! No text of specified style in document.

19-Nov-2025  Page 51

cat > rad_ca_root.cnf <<EOL
# CA Certificate Configuration Template for Root ECC Certificates
[ req ]
# Note: For ECC keys the “default_bits” option is not used.
default_md         = sha256
default_days       = 3650
prompt             = no
distinguished_name = dn
x509_extensions    = v3_ca
default_ec_curve   = prime256v1

[ dn ]
## C  = IL
## ST = TLV
## L  = Tel Aviv
## O  = RAD
## OU = RD
CN =  RADRootTestECDSA

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, keyCertSign, cRLSign
## EOL

Sign the root by itself
openssl req -config rad_ca_root.cnf -key rad_ca_root.key -new -x509 -days
3650 -sha256 -out rad_ca_root.crt

Sub CA
Generate Key using type EC and curve prime256v1(secp256r1)
Use sub-CA request configuration

Error! No text of specified style in document.

19-Nov-2025  Page 52

cat > rad_ca_sub.cnf <<EOL
# CA Certificate Configuration Template for Subordinate (Intermediate) ECC
## Certificates
[ req ]
default_bits       = 2048
default_md         = sha256
prompt             = no
distinguished_name = dn
req_extensions     = v3_intermediate

[ dn ]
## C  = IL
## ST = TLV
## L  = Tel Aviv
## O  = RAD
## OU = RD
CN = RADSubTestECDSA

[ v3_intermediate ]
subjectKeyIdentifier   = hash
#authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = keyCertSign, cRLSign
## EOL

Prepare the Sub-CA Certificate request
openssl req -config rad_ca_sub.cnf -key rad_ca_sub.key -new -out
rad_ca_sub.csr

add the Root-CA signing Server extension
cat > ca_root_ext.cnf <<EOL
[ v3_intermediate ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = digitalSignature,keyCertSign, cRLSign
crlDistributionPoints  = URI:https://openxpki.iot-rad.com:4443/downloads/crl
## EOL


Sign the sub-CSR by the root CA


Error! No text of specified style in document.

19-Nov-2025  Page 53

openssl x509 -req -in rad_ca_sub.csr -CA rad_ca_root.crt -CAkey
rad_ca_root.key -CAcreateserial -out rad_ca_sub.crt -days 3650 -sha256 -
extfile ca_root_ext.cnf -extensions v3_intermediate


this provides the certificates and keys for both root and sub CA.
2.17 Online Certificate Status Protocol (OCSP)
OCSP is A real-time certificate status checking protocol that allows clients to verify whether a digital
certificate has been revoked, without downloading the full CRL. OCSP improves performance and
bandwidth usage compared to traditional revocation lists.

In order to perform the check the user must have the following files:
- CA certificate ( can be only Sub-CA )
## 2. Certificate
Check certificate status command ca  certificate

openssl ocsp -reqout ocsp_request.der \
-CAfile ca.chain.pem \
-issuer ca.cert.pem
-cert client1.crt \
-url http://openxpki.iot-rad.com/ocsp \
-resp_text -respout ocsp_response.der

The command stdout return the certificate status
Valid certificate result :

Response verify OK
/home/rocky/pki-ocsp/cert_2.pem: good
This Update: Apr  3 13:15:21 2025 GMT
Next Update: Apr 10 13:15:21 2025 GMT

Revokes certificate result :

Error! No text of specified style in document.

19-Nov-2025  Page 54


Response verify OK
/home/rocky/pki-ocsp/cert_revoked.pem: revoked
This Update: Apr  3 13:15:57 2025 GMT
Next Update: Apr 10 13:15:57 2025 GMT
Reason: unspecified
Revocation Time: Apr  3 13:15:57 2025 GMT

the output file ocsp_response.der contains the status as well
command
openssl ocsp -respin ocsp_response.der -text -noverify
stdout
OCSP Response Data:
OCSP Response Status: successful (0x0)
Response Type: Basic OCSP Response
## Version: 1 (0x0)
Responder Id: 9DB644062A4D85759C46D1C4215F4DB7C345149D
Produced At: Apr  3 10:58:10 2025 GMT
## Responses:
Certificate ID:
Hash Algorithm: sha1
Issuer Name Hash: 616FC051FA23823B80B63EDD49EBFE18F4FB4E77
Issuer Key Hash: 9DB644062A4D85759C46D1C4215F4DB7C345149D
Serial Number: 0DCD62C3C11C144DD8AA313FF654067D3F413E5F
Cert Status: revoked
Revocation Time: Apr  3 10:58:10 2025 GMT
Revocation Reason: unspecified (0x0)
This Update: Apr  3 10:58:10 2025 GMT
Next Update: Apr 10 10:58:10 2025 GMT

The support OCSP multi certificates checks in one request
Return OCSP response if certificate is unknown to the OCSP CA responder

Certificate based Servers using OCSP
In order for TLS based Servers to use OCSP the information of the URL to check must be embedded
within the Certificate itself.
OCSP requires authorityInfoAccess (AIA)

Error! No text of specified style in document.

19-Nov-2025  Page 55


Adding attributes by following paragraph 2.5 Server Certificate Extension

Some TLS servers like HAProxy only have mode configuration attribute  the URL is taken from the
certificate attributes.





2.18 Post-Quantum  Keys

Users can issue certificate using stronger Keys algorithms
Prerequisite to do so is to add new provider (extension to openssl command)

Check if Quantum safe keys extension oqsprovider Is activated using the following command:

#run command
openssl list -providers
## #output
## Providers:
default
name: OpenSSL Default Provider
version: 3.2.2
status: active
oqsprovider
name: OpenSSL OQS Provider
version: 0.8.1-dev
status: active

Generate key

Error! No text of specified style in document.

19-Nov-2025  Page 56

openssl genpkey -algorithm mldsa44 -provider oqsprovider -out client1.key

checking all possible algorithms for the oqsprovider provider with the command:
openssl list -public-key-algorithms -provider oqsprovider

Generate request

prepare configuration to be added to the certificate request
for instance,
cat > client1.cnf <<EOL
[ req ]
default_bits       = 2048
default_md         = sha256
distinguished_name = req_distinguished_name
attributes         = req_attrs
prompt             = no

[ req_distinguished_name ]
CN                 = client1.example.com
## O                  = My Organization
## C                  = US

[ req_attrs ]
challengePassword  = SecretChallenge
## EOL

Make the request
openssl req -new -key client1.key -config client1.cnf -out client1.csr

using UI


Error! No text of specified style in document.

19-Nov-2025  Page 57



Note:  the 2.5 Enrollment using UI can’t be used for this operation, code is based on python libraries
whereas quantum safe signing is based on OS openssl in the python code.

After signing   the certificate will appear in the issued certificates table bellow




2.19 APIs

List of supported server APIs
General Server APIs

Error! No text of specified style in document.

19-Nov-2025  Page 58




SCEP supported APIs



EST supporting Apis ( curl and  estclient)


Error! No text of specified style in document.

19-Nov-2025  Page 59



OCSP supporting API


## 2.20 Inspect
User can inspect any PEM block or Base64‑encoded DER data



Error! No text of specified style in document.

19-Nov-2025  Page 60


Supported types: Certificate Signing Request, X.509 Certificate, Certificate Revocation List, PKCS#7 /
CMS, PKCS#12 / PFX, OCSP Request, OCSP Response, Private Key, Public Key
Inspect provides the designated openssl view stdout


## 2.21 Config

Config Navigation Tab shows the server current configuration, secret protected


Error! No text of specified style in document.

19-Nov-2025  Page 61


2.22 ChatPikachu
ChatPGT PGT related to the CA server features and capabilities


Error! No text of specified style in document.

19-Nov-2025  Page 62

## 2.23 Help
PDF format of this word document




Error! No text of specified style in document.

19-Nov-2025  Page 63

## 2.24 Logs
Show the server logs
Configured display:
- Show number Last Lines, default 600 lines
- Refresh by demand or every number of seconds, default 60 seconds.



Error! No text of specified style in document.

19-Nov-2025  Page 64

## Change History
Date of
## Issue
## Revisi
on
## Author Responsible Change Summary
## Page
## Count
8-Apr-2025 1.0.0 Uzi G. Asaf B. Document baseline 42
16-Apr-2025 1.0.1 Uzi G. Asaf B. Update UI, CA details, Validity time manage  43
23-Apr-2025 1.0.2 Uzi G. Asaf B. Update UI, New Navigate tabs. configuration
based
## 52
18-Jun-2025 1.0.3 Uzi G.  Add manufacture certificate URL end point, Add
generation of root and sub certificate procedure
## 57
19-Nov-2025 1.0.4 Uzi G.  OCSP tested with mocana stack, added secret
protection for various commands, added PFX
format, create profiles without templates by
editing
## 64
