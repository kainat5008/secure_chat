#!/usr/bin/env python3
"""
gen_ca.py
Create a self-signed root CA (RSA private key + X.509 certificate).
Outputs:
  certs/ca.key.pem   (PEM encoded private key, 2048-bit RSA)
  certs/ca.cert.pem  (PEM encoded self-signed X.509 certificate)
Notes:
  - Keep ca.key.pem secret. DO NOT commit it to git.
  - You can change key size or validity_period_days below.
"""

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import cryptography.x509 as x509
from datetime import datetime, timedelta
import os

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "certs")
os.makedirs(OUT_DIR, exist_ok=True)

KEY_PATH = os.path.join(OUT_DIR, "ca.key.pem")
CERT_PATH = os.path.join(OUT_DIR, "ca.cert.pem")

# Configuration - feel free to edit
KEY_SIZE = 2048
VALIDITY_DAYS = 3650  # 10 years

def generate_ca():
    # 1) Generate RSA private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)

    # 2) Build subject and issuer name (self-signed, so they are the same)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyUniversity"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])

    # 3) Build certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=5))
        .not_valid_after(datetime.utcnow() + timedelta(days=VALIDITY_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=True,
            ), critical=True
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    # 4) Write private key (PEM) and certificate (PEM)
    with open(KEY_PATH, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
                encryption_algorithm=serialization.NoEncryption(),     # no passphrase
            )
        )
    os.chmod(KEY_PATH, 0o600)

    with open(CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"CA private key written to: {KEY_PATH}")
    print(f"CA cert written to:        {CERT_PATH}")
    print("IMPORTANT: keep the CA private key secret and do NOT commit it to git.")

if __name__ == "__main__":
    generate_ca()
