"""Rebuild deterministic lab certificates using checked-in TEST ONLY RSA keys.

Requires cryptography only to regenerate fixtures; runtime and CI use stdlib ssl.
Fixed validity dates and RSA PKCS#1 signing reproduce byte-identical certificates.
Never install this CA in a system trust store or use these keys outside tests.
"""
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

ROOT=Path(__file__).parent

def key(name):
    path=ROOT/(name+'-TEST-ONLY.key')
    if not path.exists():
        value=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        path.write_bytes(value.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return serialization.load_pem_private_key(path.read_bytes(),password=None)

ca_key=key('ca'); server_key=key('server')
ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Scanix TEST ONLY CA')])
server_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'lab.scanix.invalid')])
start=datetime(2024,1,1,tzinfo=timezone.utc);end=datetime(2045,1,1,tzinfo=timezone.utc)
ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
    .serial_number(1).not_valid_before(start).not_valid_after(end)
    .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
    .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),False)
    .sign(ca_key,hashes.SHA256()))
(ROOT/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
for name,serial,issuer,signer,begin,finish in (
    ('trusted',2,ca_name,ca_key,start,end),
    ('selfsigned',3,server_name,server_key,start,end),
    ('expired',4,ca_name,ca_key,datetime(2019,1,1,tzinfo=timezone.utc),datetime(2020,1,1,tzinfo=timezone.utc))):
    cert=(x509.CertificateBuilder().subject_name(server_name).issuer_name(issuer).public_key(server_key.public_key())
          .serial_number(serial).not_valid_before(begin).not_valid_after(finish)
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
          .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),True)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False)
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('lab.scanix.invalid'),x509.DNSName('localhost'),
              x509.IPAddress(ipaddress.ip_address('127.0.0.1')),x509.IPAddress(ipaddress.ip_address('::1'))]),False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),False)
          .sign(signer,hashes.SHA256()))
    (ROOT/(name+'.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
