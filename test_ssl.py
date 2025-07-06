import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import datetime

# 服务器IP地址
server_ip = u"192.168.0.103"

# 生成 ECC 私钥，曲线选 SECP256R1（NIST P-256）
private_key = ec.generate_private_key(
    ec.SECP256R1()
)

# 证书主题
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Beijing"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Beijing"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
    x509.NameAttribute(NameOID.COMMON_NAME, server_ip),  # IP地址
])

# 构造证书
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address(server_ip))]),  # IP地址形式
        critical=False,
    )
    .sign(private_key, hashes.SHA256())
)

# 保存私钥
with open("./private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,  # ECC 推荐用 PKCS8 格式
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# 保存证书
with open("./certificate.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

with open("./certificate.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("生成针对IP访问的ECC自签名证书完成！")
