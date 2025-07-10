import os
import ipaddress
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# === 配置 ===
server_ip = "192.168.1.102"
output_dir = "../cert"
os.makedirs(output_dir, exist_ok=True)

with open(os.path.join(output_dir, "ca_key.pem"), "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)

with open(os.path.join(output_dir, "ca_cert.pem"), "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# === 生成服务器私钥和由 CA 签发的证书 ===
server_key = ec.generate_private_key(ec.SECP256R1())
server_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, server_ip),
])
server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_subject)
    .issuer_name(ca_cert.subject)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=825))
    .add_extension(
        x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address(server_ip))]),
        critical=False,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
        critical=False
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False
    )
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(
        digital_signature=True, key_encipherment=False, key_cert_sign=False, crl_sign=False,
        content_commitment=False, data_encipherment=False, key_agreement=True,
        encipher_only=False, decipher_only=False,
    ), critical=True)
    .add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False
    )
    .sign(ca_key, hashes.SHA256())
)

# 保存服务器证书和私钥
with open(os.path.join(output_dir, "server_key.pem"), "wb") as f:
    f.write(server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
with open(os.path.join(output_dir, "server_cert.pem"), "wb") as f:
    f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

print("✅ 服务器证书生成完成")
