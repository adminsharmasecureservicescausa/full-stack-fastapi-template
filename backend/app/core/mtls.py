"""Verify client certificates forwarded by a trusted reverse proxy.

TLS terminates at the proxy. The proxy checks the client certificate against
the configured CA and copies the leaf into a request header. This module
trusts that header only when the direct TCP peer is in ``MTLS_TRUSTED_PROXIES``
and then verifies the certificate again (dates, client-auth use, and CA).
Callers that are not the trusted proxy cannot supply a certificate by setting
the header themselves.
"""

import base64
import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

_PEM_BODY = re.compile(
    r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
    re.DOTALL,
)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PROVIDER = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_MAX_MATERIAL_CHARS = 20_000
_MAX_CA_BYTES = 1024 * 1024
_MAX_CHAIN = 5
_CLIENT_AUTH = x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH


class MtlsError(Exception):
    def __init__(self, detail: str, status_code: int = 400) -> None:
        self.detail = detail
        self.status_code = status_code
        super().__init__(detail)


@dataclass(frozen=True)
class VerifiedCertificate:
    fingerprint: str
    emails: tuple[str, ...]


def describe_configuration(
    *,
    enabled: bool,
    ca_file: str,
    ca_cert: str,
    trusted_proxies: str,
    provider: str,
    header_name: str,
) -> str | None:
    """Return why certificate login cannot run, or None when it is ready.

    The feature stays inactive until every check passes, including when the
    operator set ``MTLS_ENABLED`` but left the CA or the proxy list empty.
    """
    if not enabled:
        return None
    problems: list[str] = []
    proxies = trusted_proxies.strip()
    if not proxies:
        problems.append("MTLS_TRUSTED_PROXIES is empty")
    else:
        try:
            if not _parse_proxies(proxies):
                problems.append("MTLS_TRUSTED_PROXIES is empty")
        except MtlsError as exc:
            problems.append(exc.detail)
    slug = provider.strip()
    if not _PROVIDER.fullmatch(slug):
        problems.append("MTLS_PROVIDER must be a lowercase slug")
    name = header_name.strip() or "X-Forwarded-Tls-Client-Cert"
    if not _HEADER_NAME.fullmatch(name):
        problems.append("MTLS_CLIENT_CERT_HEADER is not a valid header name")
    try:
        if not load_trust_anchors(ca_file=ca_file, ca_cert=ca_cert):
            problems.append("set MTLS_CA_FILE or MTLS_CA_CERT to the client CA PEM")
    except MtlsError as exc:
        problems.append(exc.detail)
    if not problems:
        return None
    return "Client certificate login is not active: " + "; ".join(problems)


def certificate_login_ready() -> bool:
    from app.core.config import settings

    return (
        describe_configuration(
            enabled=settings.MTLS_ENABLED,
            ca_file=settings.MTLS_CA_FILE,
            ca_cert=settings.MTLS_CA_CERT,
            trusted_proxies=settings.MTLS_TRUSTED_PROXIES,
            provider=settings.MTLS_PROVIDER,
            header_name=settings.MTLS_CLIENT_CERT_HEADER,
        )
        is None
        and settings.MTLS_ENABLED
    )


def require_ready() -> None:
    from app.core.config import settings

    if not settings.MTLS_ENABLED:
        raise MtlsError("Client certificate login is disabled", status_code=404)
    if not certificate_login_ready():
        raise MtlsError("Client certificate login is not configured")


def load_trust_anchors(*, ca_file: str, ca_cert: str) -> list[x509.Certificate]:
    parts: list[str] = []
    path = ca_file.strip()
    if path:
        file = Path(path)
        if not file.is_file():
            raise MtlsError(f"MTLS_CA_FILE does not exist: {path}")
        if file.stat().st_size > _MAX_CA_BYTES:
            raise MtlsError("MTLS_CA_FILE is larger than 1MB")
        parts.append(file.read_text(encoding="utf-8"))
    inline = ca_cert.strip()
    if inline:
        parts.append(inline)
    anchors: list[x509.Certificate] = []
    for part in parts:
        try:
            anchors.extend(_certificates_in_pem(part))
        except ValueError:
            raise MtlsError("The configured client CA PEM could not be read") from None
    return anchors


def peer_is_trusted(host: str | None) -> bool:
    from app.core.config import settings

    if not host:
        return False
    try:
        peer = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped is not None:
        peer = peer.ipv4_mapped
    try:
        networks = _parse_proxies(settings.MTLS_TRUSTED_PROXIES)
    except MtlsError:
        return False
    return any(peer in network for network in networks)


def verified_certificate_from_request(
    host: str | None, header_value: str | None
) -> VerifiedCertificate:
    """Verify the proxy header, or reject it when this request is not from the proxy."""
    if not peer_is_trusted(host):
        raise MtlsError("No client certificate was presented")
    if header_value is None or not header_value.strip():
        raise MtlsError("No client certificate was presented")
    if len(header_value) > _MAX_MATERIAL_CHARS:
        raise MtlsError("Client certificate could not be read")
    try:
        certificates = parse_certificate_material(header_value)
    except ValueError:
        raise MtlsError("Client certificate could not be read") from None
    anchors = _ready_anchors()
    return verify_client_certificate(
        certificates[0], certificates[1:], trust_anchors=anchors
    )


def parse_certificate_material(value: str) -> list[x509.Certificate]:
    """Parse a PEM or the comma-separated base64 leaf Traefik forwards.

    Traefik's ``passTLSClientCert`` middleware removes the PEM armor and
    newlines, then joins certificates with commas. Other proxies forward a
    URL-encoded PEM. ``+`` in base64 is preserved (``unquote``, not
    ``unquote_plus``).
    """
    raw = value.strip()
    if not raw:
        raise ValueError("empty certificate")
    decoded = urllib.parse.unquote(raw).strip()
    if "BEGIN CERTIFICATE" in decoded:
        certificates = _certificates_in_pem(decoded)
    else:
        parts = [part.strip() for part in decoded.split(",") if part.strip()]
        if not parts or len(parts) > _MAX_CHAIN:
            raise ValueError("empty certificate")
        certificates = [_certificate_from_base64(part) for part in parts]
    if not certificates or len(certificates) > _MAX_CHAIN:
        raise ValueError("empty certificate")
    return certificates


def verify_client_certificate(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    *,
    trust_anchors: list[x509.Certificate],
) -> VerifiedCertificate:
    if not trust_anchors:
        raise MtlsError("Client certificate login is not configured")
    _reject_unusable_leaf(leaf)
    _check_validity(leaf)
    _require_client_auth(leaf)
    store = Store(trust_anchors)
    verifier = PolicyBuilder().store(store).build_client_verifier()
    candidates = [intermediates] if intermediates else [[]]
    if intermediates:
        candidates.append([])
    failures: list[VerificationError] = []
    for chain in candidates:
        try:
            verifier.verify(leaf, chain)
        except VerificationError as exc:
            failures.append(exc)
            continue
        failures = []
        break
    if failures:
        if all("2.5.29.17" in str(exc) for exc in failures):
            raise MtlsError(
                "Client certificate must include a subject alternative name"
            )
        raise MtlsError("Client certificate was not issued by the trusted CA")
    return VerifiedCertificate(
        fingerprint=fingerprint_sha256(leaf),
        emails=certificate_emails(leaf),
    )


def fingerprint_sha256(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex()


def certificate_emails(certificate: x509.Certificate) -> tuple[str, ...]:
    found: list[str] = []
    try:
        sans = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        found.extend(str(email) for email in sans.get_values_for_type(x509.RFC822Name))
    except x509.ExtensionNotFound:
        pass
    for attribute in certificate.subject:
        if attribute.oid == x509.NameOID.EMAIL_ADDRESS:
            found.append(str(attribute.value))
    unique: list[str] = []
    for email in found:
        lowered = email.strip().lower()
        if "@" not in lowered or lowered in unique:
            continue
        unique.append(lowered)
    return tuple(unique)


def assert_public_pem(pem: str) -> None:
    if _PRIVATE_KEY.search(pem):
        raise MtlsError(
            "This file contains a private key. Upload only the public certificate."
        )


def verify_uploaded_pem(pem: str) -> VerifiedCertificate:
    assert_public_pem(pem)
    if len(pem) > _MAX_MATERIAL_CHARS:
        raise MtlsError("Client certificate could not be read")
    try:
        certificates = parse_certificate_material(pem)
    except ValueError:
        raise MtlsError("Client certificate could not be read") from None
    return verify_client_certificate(
        certificates[0], certificates[1:], trust_anchors=_ready_anchors()
    )


def _ready_anchors() -> list[x509.Certificate]:
    from app.core.config import settings

    try:
        return load_trust_anchors(
            ca_file=settings.MTLS_CA_FILE, ca_cert=settings.MTLS_CA_CERT
        )
    except MtlsError:
        raise MtlsError("Client certificate login is not configured") from None


def _parse_proxies(value: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in value.split(","):
        item = part.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            raise MtlsError(
                f"MTLS_TRUSTED_PROXIES has an invalid entry: {item}"
            ) from None
    return networks


def _certificates_in_pem(text: str) -> list[x509.Certificate]:
    bodies = _PEM_BODY.findall(text)
    if "BEGIN CERTIFICATE" in text and not bodies:
        raise ValueError("malformed pem")
    if len(bodies) > _MAX_CHAIN:
        raise ValueError("too many certificates")
    return [_certificate_from_base64(body) for body in bodies]


def _certificate_from_base64(body: str) -> x509.Certificate:
    compact = re.sub(r"\s+", "", urllib.parse.unquote(body))
    if not compact:
        raise ValueError("empty certificate")
    try:
        der = base64.b64decode(compact, validate=True)
        return x509.load_der_x509_certificate(der)
    except ValueError:
        try:
            der = base64.b64decode(compact)
            return x509.load_der_x509_certificate(der)
        except ValueError:
            raise ValueError("malformed certificate") from None


def _reject_unusable_leaf(certificate: x509.Certificate) -> None:
    try:
        basic = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound:
        return
    if basic.ca:
        raise MtlsError("Client certificate cannot be used for sign-in")


def _check_validity(certificate: x509.Certificate) -> None:
    now = datetime.now(UTC)
    if certificate.not_valid_before_utc > now:
        raise MtlsError("Client certificate is not valid yet")
    if certificate.not_valid_after_utc <= now:
        raise MtlsError("Client certificate is expired")


def _require_client_auth(certificate: x509.Certificate) -> None:
    try:
        extended = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound:
        raise MtlsError(
            "Client certificate is not authorized for client authentication"
        ) from None
    if _CLIENT_AUTH not in extended:
        raise MtlsError(
            "Client certificate is not authorized for client authentication"
        )
