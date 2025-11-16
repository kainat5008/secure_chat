#!/usr/bin/env python3
"""
gen_cert.py
Generate an RSA keypair + X.509 certificate signed by the root CA created by gen_ca.py.

Usage:
  python scripts/gen_cert.py --cn "server.securechat.local" --out server

Outputs (written into certs/):
  certs/server.key.pem   (private key)
  certs/server.cert.pem  (certificate signed by CA)

Example:
  python scripts/gen_cert.py --cn "client1" --out client1 --is-client
"""

import argparse
import os
from datetime import datetime, timedelta
import cryptography.x509 as x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
CERTS_DIR = os.path.join(BASE_DIR, "certs")
CA_KEY_PATH = os.path.join(CERTS_DIR, "ca.key.pem")
CA_CERT_PATH = os.path.join(CERTS_DIR, "ca.cert.pem")

KEY_SIZE = 2048
VALIDITY_DAYS = 365  # 1 year

def load_ca():
    # Load CA private key and cert (must exist)
    if not os.path.exists(CA_KEY_PATH) or not os.path.exists(CA_CERT_PATH):
        raise FileNotFoundError("CA key or cert not found. Run gen_ca.py first.")

    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    return ca_key, ca_cert

def generate_signed_cert(common_name: str, out_basename: str, is_client: bool = False):
    os.makedirs(CERTS_DIR, exist_ok=True)
    ca_key, ca_cert = load_ca()

    # 1) Generate key for subject
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)

    # 2) Build subject name
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat Users"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # 3) Build certificate builder
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=5))
        .not_valid_after(datetime.utcnow() + timedelta(days=VALIDITY_DAYS))
    )

    # 4) Add extensions: EKU (clientAuth or serverAuth) and BasicConstraints (not CA)
    if is_client:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]), critical=False
        )
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]), critical=False
        )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )

    # Optionally add SubjectAlternativeName (SAN) — include CN as DNSName
    san = x509.SubjectAlternativeName([x509.DNSName(common_name)])
    builder = builder.add_extension(san, critical=False)

    # 5) Sign with CA private key
    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # 6) Persist key and cert
    key_path = os.path.join(CERTS_DIR, f"{out_basename}.key.pem")
    cert_path = os.path.join(CERTS_DIR, f"{out_basename}.cert.pem")

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(key_path, 0o600)

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Wrote key -> {key_path}")
    print(f"Wrote cert-> {cert_path}")
    return key_path, cert_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate cert signed by local CA")
    parser.add_argument("--cn", required=True, help="Common Name (CN) for certificate (e.g. server.local)")
    parser.add_argument("--out", required=True, help="Base output name (e.g. server1 or client1)")
    parser.add_argument("--is-client", action="store_true", help="If set, mark EKU as clientAuth")
    args = parser.parse_args()

    generate_signed_cert(args.cn, args.out, is_client=args.is_client)
