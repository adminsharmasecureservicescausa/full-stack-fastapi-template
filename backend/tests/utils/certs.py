import base64
import urllib.parse
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(common_name: str, email: str | None = None) -> x509.Name:
    attributes: list[x509.NameAttribute] = [
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ]
    if email is not None:
        attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    return x509.Name(attributes)


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_ca(
    *,
    common_name: str = "Test Client CA",
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _key()
    now = datetime.now(UTC)
    subject = _name(common_name)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(days=1))
        .not_valid_after(not_after or now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def make_client(
    ca_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
    *,
    email: str,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    extended_key_usage: list[x509.ObjectIdentifier] | None = None,
    is_ca: bool = False,
    include_email_san: bool = True,
    include_subject_email: bool = True,
    dns_names: list[str] | None = None,
) -> x509.Certificate:
    key = _key()
    now = datetime.now(UTC)
    # emailAddress and commonName are limited to 64 characters. The account
    # address is carried in the SAN, which is what sign-in matches.
    subject_email = email if include_subject_email and len(email) <= 64 else None
    common_name = email if len(email) <= 64 else "client"
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name, subject_email))
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(hours=1))
        .not_valid_after(not_after or now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    alt_names: list[x509.GeneralName] = []
    if include_email_san:
        alt_names.append(x509.RFC822Name(email))
    for dns_name in dns_names or []:
        alt_names.append(x509.DNSName(dns_name))
    if alt_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(alt_names), critical=False
        )
    usages = (
        [ExtendedKeyUsageOID.CLIENT_AUTH]
        if extended_key_usage is None
        else extended_key_usage
    )
    if usages:
        builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=False)
    return builder.sign(ca_key, hashes.SHA256())


def certificate_pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def traefik_header(*certificates: x509.Certificate) -> str:
    """Match Traefik passTLSClientCert: bare base64 bodies joined by commas."""
    bodies: list[str] = []
    for certificate in certificates:
        pem = certificate_pem(certificate)
        bodies.append(
            pem.replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("\n", "")
        )
    return ",".join(bodies)


def urlencoded_pem(certificate: x509.Certificate) -> str:
    return urllib.parse.quote(certificate_pem(certificate), safe="")


def private_key_pem() -> str:
    key = _key()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def b64_body(certificate: x509.Certificate) -> str:
    der = certificate.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode()
