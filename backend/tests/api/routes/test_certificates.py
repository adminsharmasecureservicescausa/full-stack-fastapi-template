import uuid
import warnings
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app import crud
from app.core.config import Settings, settings
from app.core.mtls import fingerprint_sha256, peer_is_trusted
from app.main import app
from app.models import ExternalIdentity, IdentityType, UserCreate
from tests.utils.certs import (
    certificate_pem,
    make_ca,
    make_client,
    private_key_pem,
    traefik_header,
    urlencoded_pem,
)
from tests.utils.user import user_authentication_headers
from tests.utils.utils import random_email

HEADER = "X-Forwarded-Tls-Client-Cert"
TRUSTED_HOST = "10.0.0.8"
API = settings.API_V1_STR


def _enable(
    monkeypatch: pytest.MonkeyPatch,
    ca_pem: str,
    *,
    enabled: bool = True,
    proxies: str = TRUSTED_HOST,
    match_email: bool = False,
    ca_file: str = "",
) -> None:
    monkeypatch.setattr(settings, "MTLS_ENABLED", enabled)
    monkeypatch.setattr(settings, "MTLS_CA_CERT", ca_pem)
    monkeypatch.setattr(settings, "MTLS_CA_FILE", ca_file)
    monkeypatch.setattr(settings, "MTLS_TRUSTED_PROXIES", proxies)
    monkeypatch.setattr(settings, "MTLS_PROVIDER", "client-ca")
    monkeypatch.setattr(settings, "MTLS_MATCH_EMAIL", match_email)
    monkeypatch.setattr(settings, "MTLS_CLIENT_CERT_HEADER", HEADER)


@pytest.fixture
def trusted_client() -> Generator[TestClient]:
    with TestClient(app, client=(TRUSTED_HOST, 443)) as test_client:
        yield test_client


def _password() -> str:
    return "supersecret1"


def _create_user(db: Session, email: str | None = None) -> tuple[str, str]:
    address = email or random_email()
    password = _password()
    crud.create_user(
        session=db, user_create=UserCreate(email=address, password=password)
    )
    return address, password


def _auth(client: TestClient, email: str, password: str) -> dict[str, str]:
    return user_authentication_headers(client=client, email=email, password=password)


def _login(
    client: TestClient, certificate: x509.Certificate, *, style: str = "traefik"
):
    if style == "pem":
        value = certificate_pem(certificate)
    elif style == "urlencoded":
        value = urlencoded_pem(certificate)
    else:
        value = traefik_header(certificate)
    return client.post(f"{API}/login/certificate", headers={HEADER: value})


def _issued(
    email: str,
    *,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    extended_key_usage: list[x509.ObjectIdentifier] | None = None,
    include_email_san: bool = True,
    include_subject_email: bool = True,
) -> tuple[str, x509.Certificate, x509.Certificate]:
    ca_key, ca_certificate = make_ca()
    leaf = make_client(
        ca_key,
        ca_certificate,
        email=email,
        not_before=not_before,
        not_after=not_after,
        extended_key_usage=extended_key_usage,
        include_email_san=include_email_san,
        include_subject_email=include_subject_email,
    )
    return certificate_pem(ca_certificate), leaf, ca_certificate


def test_certificate_login_is_disabled_by_default(client: TestClient) -> None:
    response = client.get(f"{API}/login/certificate")
    assert response.status_code == 200
    assert response.json() == {"enabled": False}
    rejected = client.post(f"{API}/login/certificate", headers={HEADER: "aaaa"})
    assert rejected.status_code == 404
    assert rejected.json()["detail"] == "Client certificate login is disabled"


def test_login_with_a_linked_certificate(
    client: TestClient,
    trusted_client: TestClient,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email, password = _create_user(db)
    ca_pem, leaf, _ca = _issued(email)
    _enable(monkeypatch, ca_pem)
    headers = _auth(client, email, password)
    linked = client.post(
        f"{API}/users/me/certificates",
        headers=headers,
        json={"pem": certificate_pem(leaf)},
    )
    assert linked.status_code == 200
    body = linked.json()
    assert body["fingerprint"] == fingerprint_sha256(leaf)
    assert body["email"] == email.lower()
    assert body["provider"] == "client-ca"

    token = _login(trusted_client, leaf)
    assert token.status_code == 200
    access = token.json()["access_token"]
    me = trusted_client.get(
        f"{API}/users/me", headers={"Authorization": f"Bearer {access}"}
    )
    assert me.status_code == 200
    assert me.json()["email"] == email


@pytest.mark.parametrize("style", ["pem", "urlencoded", "traefik"])
def test_login_accepts_proxy_header_formats(
    client: TestClient,
    trusted_client: TestClient,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
    style: str,
) -> None:
    email, password = _create_user(db)
    ca_pem, leaf, ca_certificate = _issued(email)
    _enable(monkeypatch, ca_pem)
    headers = _auth(client, email, password)
    assert (
        client.post(
            f"{API}/users/me/certificates",
            headers=headers,
            json={"pem": certificate_pem(leaf)},
        ).status_code
        == 200
    )
    value = traefik_header(leaf, ca_certificate) if style == "traefik" else None
    if style == "traefik":
        response = trusted_client.post(
            f"{API}/login/certificate", headers={HEADER: value}
        )
    else:
        response = _login(trusted_client, leaf, style=style)
    assert response.status_code == 200


def test_unknown_certificate_is_rejected(
    trusted_client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    email, _password = _create_user(db)
    ca_pem, leaf, _ca = _issued(email)
    _enable(monkeypatch, ca_pem)
    response = _login(trusted_client, leaf)
    assert response.status_code == 400
    assert response.json()["detail"] == "Unknown certificate"
    rows = db.exec(
        select(ExternalIdentity).where(
            ExternalIdentity.subject == fingerprint_sha256(leaf)
        )
    ).all()
    assert rows == []


def test_expired_certificate_is_rejected(
    trusted_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.now(UTC)
    ca_pem, leaf, _ca = _issued(
        random_email(),
        not_before=now - timedelta(days=10),
        not_after=now - timedelta(days=1),
    )
    _enable(monkeypatch, ca_pem)
    response = _login(trusted_client, leaf)
    assert response.status_code == 400
    assert response.json()["detail"] == "Client certificate is expired"


def test_not_yet_valid_certificate_is_rejected(
    trusted_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.now(UTC)
    ca_pem, leaf, _ca = _issued(
        random_email(),
        not_before=now + timedelta(days=2),
        not_after=now + timedelta(days=3),
    )
    _enable(monkeypatch, ca_pem)
    response = _login(trusted_client, leaf)
    assert response.status_code == 400
    assert response.json()["detail"] == "Client certificate is not valid yet"


def test_untrusted_certificate_is_rejected(
    trusted_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted_pem, _trusted_leaf, _trusted_ca = _issued(random_email())
    _other_pem, other_leaf, _other_ca = _issued(random_email())
    _enable(monkeypatch, trusted_pem)
    response = _login(trusted_client, other_leaf)
    assert response.status_code == 400
    assert (
        response.json()["detail"]
        == "Client certificate was not issued by the trusted CA"
    )


def test_ca_certificate_and_wrong_eku_are_rejected(
    trusted_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ca_key, ca_certificate = make_ca()
    _enable(monkeypatch, certificate_pem(ca_certificate))
    presented_ca = trusted_client.post(
        f"{API}/login/certificate",
        headers={HEADER: traefik_header(ca_certificate)},
    )
    assert presented_ca.status_code == 400
    assert (
        presented_ca.json()["detail"] == "Client certificate cannot be used for sign-in"
    )

    ca_pem, server_leaf, _ca = _issued(
        random_email(),
        extended_key_usage=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    _enable(monkeypatch, ca_pem)
    server_only = _login(trusted_client, server_leaf)
    assert server_only.status_code == 400
    assert (
        server_only.json()["detail"]
        == "Client certificate is not authorized for client authentication"
    )

    missing_san_pem, missing_san, _missing_ca = _issued(
        random_email(), include_email_san=False, include_subject_email=False
    )
    _enable(monkeypatch, missing_san_pem)
    without_san = _login(trusted_client, missing_san)
    assert without_san.status_code == 400
    assert (
        without_san.json()["detail"]
        == "Client certificate must include a subject alternative name"
    )


def test_spoofed_header_is_ignored_without_the_trusted_proxy(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    email, password = _create_user(db)
    ca_pem, leaf, _ca = _issued(email)
    _enable(monkeypatch, ca_pem, proxies=TRUSTED_HOST)
    headers = _auth(client, email, password)
    assert (
        client.post(
            f"{API}/users/me/certificates",
            headers=headers,
            json={"pem": certificate_pem(leaf)},
        ).status_code
        == 200
    )
    spoofed = client.post(
        f"{API}/login/certificate",
        headers={
            HEADER: traefik_header(leaf),
            "X-Forwarded-For": TRUSTED_HOST,
        },
    )
    assert spoofed.status_code == 400
    assert spoofed.json()["detail"] == "No client certificate was presented"
    assert "access_token" not in spoofed.json()


def test_disabled_feature_ignores_a_valid_proxy_certificate(
    client: TestClient,
    trusted_client: TestClient,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email, password = _create_user(db)
    ca_pem, leaf, _ca = _issued(email)
    _enable(monkeypatch, ca_pem, enabled=True)
    headers = _auth(client, email, password)
    client.post(
        f"{API}/users/me/certificates",
        headers=headers,
        json={"pem": certificate_pem(leaf)},
    )
    _enable(monkeypatch, ca_pem, enabled=False)
    response = _login(trusted_client, leaf)
    assert response.status_code == 404
    assert response.json()["detail"] == "Client certificate login is disabled"
    status = trusted_client.get(f"{API}/login/certificate")
    assert status.json()["enabled"] is False


def test_incomplete_configuration_does_not_trust_the_header(
    trusted_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca_pem, leaf, _ca = _issued(random_email())
    _enable(monkeypatch, ca_pem, proxies="")
    response = _login(trusted_client, leaf)
    assert response.status_code == 400
    assert response.json()["detail"] == "Client certificate login is not configured"
    assert trusted_client.get(f"{API}/login/certificate").json()["enabled"] is False

    _enable(monkeypatch, "not a certificate", proxies=TRUSTED_HOST)
    invalid = _login(trusted_client, leaf)
    assert invalid.status_code == 400
    assert invalid.json()["detail"] == "Client certificate login is not configured"


def test_garbage_header_from_the_trusted_proxy_is_rejected(
    trusted_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca_pem, _leaf, _ca = _issued(random_email())
    _enable(monkeypatch, ca_pem)
    response = trusted_client.post(
        f"{API}/login/certificate", headers={HEADER: "this-is-not-a-certificate"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Client certificate could not be read"
    missing = trusted_client.post(f"{API}/login/certificate")
    assert missing.status_code == 400
    assert missing.json()["detail"] == "No client certificate was presented"


def test_link_unlink_and_link_the_presented_certificate(
    client: TestClient,
    trusted_client: TestClient,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email, password = _create_user(db)
    ca_pem, leaf, _ca = _issued(email)
    _enable(monkeypatch, ca_pem)
    headers = _auth(client, email, password)
    first = client.post(
        f"{API}/users/me/certificates",
        headers=headers,
        json={"pem": certificate_pem(leaf)},
    )
    assert first.status_code == 200
    certificate_id = first.json()["id"]
    again = client.post(
        f"{API}/users/me/certificates",
        headers=headers,
        json={"pem": certificate_pem(leaf)},
    )
    assert again.status_code == 200
    assert again.json()["id"] == certificate_id

    listed = client.get(f"{API}/users/me/certificates", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["count"] == 1

    removed = client.delete(
        f"{API}/users/me/certificates/{certificate_id}", headers=headers
    )
    assert removed.status_code == 200
    assert removed.json()["message"] == "Certificate unlinked"
    assert _login(trusted_client, leaf).json()["detail"] == "Unknown certificate"

    presented = trusted_client.post(
        f"{API}/users/me/certificates/current",
        headers={**headers, HEADER: traefik_header(leaf)},
    )
    assert presented.status_code == 200
    assert presented.json()["fingerprint"] == fingerprint_sha256(leaf)
    assert _login(trusted_client, leaf).status_code == 200

    missing = client.delete(
        f"{API}/users/me/certificates/{uuid.uuid4()}", headers=headers
    )
    assert missing.status_code == 404


def test_upload_rejects_private_keys_and_certificates_for_someone_else(
    client: TestClient,
    trusted_client: TestClient,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email, password = _create_user(db)
    other, other_password = _create_user(db)
    ca_key, ca_certificate = make_ca()
    ca_pem = certificate_pem(ca_certificate)
    other_leaf = make_client(ca_key, ca_certificate, email=other)
    no_email_leaf = make_client(
        ca_key,
        ca_certificate,
        email="noemail",
        include_email_san=False,
        include_subject_email=False,
        dns_names=["client.example"],
    )
    _enable(monkeypatch, ca_pem)
    headers = _auth(client, email, password)

    private = client.post(
        f"{API}/users/me/certificates",
        headers=headers,
        json={"pem": private_key_pem()},
    )
    assert private.status_code == 400
    assert "private key" in private.json()["detail"]

    mismatch = client.post(
        f"{API}/users/me/certificates",
        headers=headers,
        json={"pem": certificate_pem(other_leaf)},
    )
    assert mismatch.status_code == 400
    assert mismatch.json()["detail"] == "Certificate email does not match this account"

    missing_email = client.post(
        f"{API}/users/me/certificates",
        headers=headers,
        json={"pem": certificate_pem(no_email_leaf)},
    )
    assert missing_email.status_code == 400
    assert "no email address" in missing_email.json()["detail"]

    owner_headers = _auth(client, other, other_password)
    assert (
        client.post(
            f"{API}/users/me/certificates",
            headers=owner_headers,
            json={"pem": certificate_pem(other_leaf)},
        ).status_code
        == 200
    )
    stolen = trusted_client.post(
        f"{API}/users/me/certificates/current",
        headers={**headers, HEADER: traefik_header(other_leaf)},
    )
    assert stolen.status_code == 409
    assert stolen.json()["detail"] == "Certificate is already linked to another account"


def test_email_match_links_on_first_login_and_can_be_disabled(
    trusted_client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    email, _password = _create_user(db)
    ca_pem, leaf, _ca = _issued(email.upper())
    _enable(monkeypatch, ca_pem, match_email=False)
    refused = _login(trusted_client, leaf)
    assert refused.status_code == 400
    assert refused.json()["detail"] == "Unknown certificate"

    _enable(monkeypatch, ca_pem, match_email=True)
    allowed = _login(trusted_client, leaf)
    assert allowed.status_code == 200
    db.expire_all()
    identity = db.exec(
        select(ExternalIdentity).where(
            ExternalIdentity.subject == fingerprint_sha256(leaf)
        )
    ).one()
    assert identity.identity_type == IdentityType.MTLS
    assert identity.email == email.lower()


def test_admin_can_list_and_revoke_certificates(
    client: TestClient,
    trusted_client: TestClient,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
    superuser_token_headers: dict[str, str],
    normal_user_token_headers: dict[str, str],
) -> None:
    email, password = _create_user(db)
    ca_pem, leaf, _ca = _issued(email)
    _enable(monkeypatch, ca_pem)
    headers = _auth(client, email, password)
    linked = client.post(
        f"{API}/users/me/certificates",
        headers=headers,
        json={"pem": certificate_pem(leaf)},
    )
    certificate_id = linked.json()["id"]
    user = crud.get_user_by_email(session=db, email=email)
    assert user is not None

    forbidden = client.get(
        f"{API}/users/{user.id}/certificates", headers=normal_user_token_headers
    )
    assert forbidden.status_code == 403

    visible = client.get(
        f"{API}/users/{user.id}/certificates", headers=superuser_token_headers
    )
    assert visible.status_code == 200
    assert visible.json()["data"][0]["fingerprint"] == fingerprint_sha256(leaf)

    revoked = client.delete(
        f"{API}/users/{user.id}/certificates/{certificate_id}",
        headers=superuser_token_headers,
    )
    assert revoked.status_code == 200
    assert revoked.json()["message"] == "Certificate revoked"
    assert _login(trusted_client, leaf).json()["detail"] == "Unknown certificate"

    missing_user = client.get(
        f"{API}/users/{uuid.uuid4()}/certificates", headers=superuser_token_headers
    )
    assert missing_user.status_code == 404


def test_certificate_routes_do_not_remove_oauth_identities(
    client: TestClient,
    db: Session,
    superuser_token_headers: dict[str, str],
) -> None:
    email, password = _create_user(db)
    user = crud.get_user_by_email(session=db, email=email)
    assert user is not None
    identity = ExternalIdentity(
        user_id=user.id,
        identity_type=IdentityType.OIDC,
        provider="google",
        subject="google-subject",
        email=email,
    )
    db.add(identity)
    db.commit()
    db.refresh(identity)
    headers = _auth(client, email, password)
    response = client.delete(
        f"{API}/users/me/certificates/{identity.id}", headers=headers
    )
    assert response.status_code == 404
    admin = client.delete(
        f"{API}/users/{user.id}/certificates/{identity.id}",
        headers=superuser_token_headers,
    )
    assert admin.status_code == 404
    assert db.get(ExternalIdentity, identity.id) is not None


def test_inactive_user_cannot_sign_in_with_a_certificate(
    client: TestClient,
    trusted_client: TestClient,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email, password = _create_user(db)
    ca_pem, leaf, _ca = _issued(email)
    _enable(monkeypatch, ca_pem)
    headers = _auth(client, email, password)
    client.post(
        f"{API}/users/me/certificates",
        headers=headers,
        json={"pem": certificate_pem(leaf)},
    )
    user = crud.get_user_by_email(session=db, email=email)
    assert user is not None
    user.is_active = False
    db.add(user)
    db.commit()
    response = _login(trusted_client, leaf)
    assert response.status_code == 400
    assert response.json()["detail"] == "Inactive user"


def test_ca_file_is_accepted(
    client: TestClient,
    trusted_client: TestClient,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    email, password = _create_user(db)
    ca_pem, leaf, _ca = _issued(email)
    ca_path = tmp_path / "client-ca.pem"
    ca_path.write_text(ca_pem, encoding="utf-8")
    _enable(monkeypatch, "", ca_file=str(ca_path))
    headers = _auth(client, email, password)
    assert (
        client.post(
            f"{API}/users/me/certificates",
            headers=headers,
            json={"pem": certificate_pem(leaf)},
        ).status_code
        == 200
    )
    assert _login(trusted_client, leaf).status_code == 200


def test_proxy_matching_ignores_names_and_accepts_mapped_ipv4(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "MTLS_TRUSTED_PROXIES", "10.0.0.8")
    assert peer_is_trusted("::ffff:10.0.0.8") is True
    assert peer_is_trusted("10.0.0.9") is False
    assert peer_is_trusted("testclient") is False
    assert peer_is_trusted(None) is False
    monkeypatch.setattr(settings, "MTLS_TRUSTED_PROXIES", "not-a-network")
    assert peer_is_trusted("10.0.0.8") is False


def test_settings_warns_when_certificate_login_is_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MTLS_ENABLED", "true")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        loaded = Settings()
    assert loaded.MTLS_ENABLED is True
    assert any(
        "Client certificate login is not active" in str(item.message) for item in caught
    )


def test_link_certificate_identity_survives_a_concurrent_insert(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = crud.create_user(
        session=db,
        user_create=UserCreate(email=random_email(), password=_password()),
    )
    commits = {"count": 0}
    original_commit = db.commit

    def commit_then_conflict() -> None:
        commits["count"] += 1
        original_commit()
        if commits["count"] == 1:
            raise IntegrityError("INSERT", {}, Exception("duplicate subject"))

    monkeypatch.setattr(db, "commit", commit_then_conflict)
    identity = crud.link_certificate_identity(
        session=db,
        user_id=user.id,
        provider="client-ca",
        fingerprint="a" * 64,
        email=user.email,
    )
    assert identity.user_id == user.id


def test_presented_certificate_requires_the_trusted_proxy(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    email, password = _create_user(db)
    ca_pem, leaf, _ca = _issued(email)
    _enable(monkeypatch, ca_pem)
    headers = _auth(client, email, password)
    response = client.post(
        f"{API}/users/me/certificates/current",
        headers={**headers, HEADER: traefik_header(leaf)},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "No client certificate was presented"
