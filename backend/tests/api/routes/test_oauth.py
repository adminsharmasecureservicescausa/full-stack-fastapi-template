import base64
import hashlib
import json
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, func, select

from app import crud
from app.core.config import settings
from app.core.oauth import OAUTH_TXN_COOKIE, STATE_ERROR, UNVERIFIED_EMAIL
from app.models import ExternalIdentity, IdentityType, User, UserCreate
from tests.utils.utils import random_email, random_lower_string

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PRIVATE_PEM = _PRIVATE_KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
_PUBLIC_NUMBERS = _PRIVATE_KEY.public_key().public_numbers()
_ISSUER = "https://issuer.example.test"
_JWKS_URL = f"{_ISSUER}/jwks"
_TOKEN_URL = f"{_ISSUER}/token"


def _b64u(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).decode().rstrip("=")


_JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "test-key",
            "use": "sig",
            "alg": "RS256",
            "n": _b64u(_PUBLIC_NUMBERS.n),
            "e": _b64u(_PUBLIC_NUMBERS.e),
        }
    ]
}
_DISCOVERY = {
    "issuer": _ISSUER,
    "authorization_endpoint": f"{_ISSUER}/authorize",
    "token_endpoint": _TOKEN_URL,
    "jwks_uri": _JWKS_URL,
}


def _id_token(**overrides: Any) -> str:
    claims: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": "google-client",
        "sub": "google-subject-1",
        "email": "oauth-user@example.com",
        "email_verified": True,
        "name": "OAuth User",
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
    }
    claims.update(overrides)
    return jwt.encode(
        claims, _PRIVATE_PEM, algorithm="RS256", headers={"kid": "test-key"}
    )


class ProviderAPI:
    def __init__(self) -> None:
        self.id_token = _id_token()
        self.github_user: dict[str, Any] = {
            "id": 4242,
            "name": "Octo Cat",
            "login": "octocat",
        }
        self.github_emails: list[Any] = [
            {
                "email": "other@example.com",
                "primary": False,
                "verified": True,
            },
            {
                "email": "octo@example.com",
                "primary": True,
                "verified": True,
            },
        ]
        self.token_bodies: list[str] = []
        self.fail_discovery = False
        self.discovery_document: dict[str, Any] | None = None
        self.token_payload: dict[str, Any] | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url.copy_with(query=None))
        if url == "https://accounts.google.com/.well-known/openid-configuration":
            if self.fail_discovery:
                return httpx.Response(500, json={"error": "down"})
            return httpx.Response(200, json=self.discovery_document or _DISCOVERY)
        if url == "https://auth.example.test/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    **_DISCOVERY,
                    "issuer": "https://auth.example.test",
                    "authorization_endpoint": "https://auth.example.test/authorize",
                    "token_endpoint": "https://auth.example.test/token",
                },
            )
        if url in {_JWKS_URL, "https://auth.example.test/jwks"}:
            return httpx.Response(200, json=_JWKS)
        if url in {_TOKEN_URL, "https://auth.example.test/token"}:
            self.token_bodies.append(request.content.decode())
            payload = self.token_payload or {
                "access_token": "provider-access",
                "id_token": self.id_token,
                "token_type": "Bearer",
            }
            return httpx.Response(200, json=payload)
        if url == "https://github.com/login/oauth/access_token":
            self.token_bodies.append(request.content.decode())
            return httpx.Response(
                200, json={"access_token": "github-access", "token_type": "bearer"}
            )
        if url == "https://api.github.com/user":
            return httpx.Response(200, json=self.github_user)
        if url == "https://api.github.com/user/emails":
            return httpx.Response(200, json=self.github_emails)
        return httpx.Response(404, json={"error": "unmocked", "url": url})


@pytest.fixture
def oauth_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "google-client")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "google-secret")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "github-client")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "github-secret")
    monkeypatch.setattr(settings, "OIDC_PROVIDERS", "")
    monkeypatch.setattr(settings, "FRONTEND_HOST", "http://localhost:5173")


@pytest.fixture
def provider_api(monkeypatch: pytest.MonkeyPatch) -> ProviderAPI:
    api = ProviderAPI()

    def factory() -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(api.handler))

    monkeypatch.setattr("app.core.oauth.http_client", factory)
    return api


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _authorize(client: TestClient, provider: str) -> tuple[str, str]:
    response = client.get(
        f"{settings.API_V1_STR}/login/oauth/{provider}/authorize",
        follow_redirects=False,
    )
    assert response.status_code == 302
    location = response.headers["location"]
    assert "client_secret" not in location
    assert "code_verifier" not in location
    query = parse_qs(urlparse(location).query)
    assert query["code_challenge_method"] == ["S256"]
    state = query["state"][0]
    txn = jwt.decode(
        response.cookies[OAUTH_TXN_COOKIE],
        settings.SECRET_KEY,
        algorithms=["HS256"],
    )
    assert txn["typ"] == "oauth_txn"
    assert txn["state"] == state
    assert txn["provider"] == provider
    assert query["code_challenge"] == [_pkce_challenge(txn["cv"])]
    assert query["redirect_uri"] == ["http://localhost:5173/oauth/callback"]
    return state, location


def _callback(
    client: TestClient, state: str, code: str = "auth-code"
) -> httpx.Response:
    return client.post(
        f"{settings.API_V1_STR}/login/oauth/callback",
        json={"code": code, "state": state},
    )


def test_providers_hidden_until_configured(client: TestClient) -> None:
    response = client.get(f"{settings.API_V1_STR}/login/oauth/providers")
    assert response.status_code == 200
    assert response.json() == {"data": []}


@pytest.mark.usefixtures("oauth_settings")
def test_providers_lists_enabled(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = client.get(f"{settings.API_V1_STR}/login/oauth/providers")
    assert response.status_code == 200
    assert response.json()["data"] == [
        {"id": "google", "name": "Google"},
        {"id": "github", "name": "GitHub"},
    ]
    monkeypatch.setattr(
        settings,
        "OIDC_PROVIDERS",
        json.dumps(
            [
                {
                    "id": "auth0",
                    "name": "Auth0",
                    "client_id": "auth0-client",
                    "client_secret": "auth0-secret",
                    "discovery_url": (
                        "https://auth.example.test/.well-known/openid-configuration"
                    ),
                }
            ]
        ),
    )
    response = client.get(f"{settings.API_V1_STR}/login/oauth/providers")
    assert response.json()["data"][-1] == {"id": "auth0", "name": "Auth0"}


def test_providers_reject_invalid_configuration(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "OIDC_PROVIDERS", "{")
    response = client.get(f"{settings.API_V1_STR}/login/oauth/providers")
    assert response.status_code == 500
    assert response.json()["detail"] == "OIDC_PROVIDERS is not valid JSON"


@pytest.mark.usefixtures("oauth_settings")
def test_authorize_unknown_provider(client: TestClient) -> None:
    response = client.get(
        f"{settings.API_V1_STR}/login/oauth/missing/authorize",
        follow_redirects=False,
    )
    assert response.status_code == 404


@pytest.mark.usefixtures("oauth_settings")
def test_google_login_creates_user_and_jwt(
    client: TestClient,
    db: Session,
    provider_api: ProviderAPI,
) -> None:
    state, location = _authorize(client, "google")
    assert location.startswith(f"{_ISSUER}/authorize?")
    response = _callback(client, state)
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert OAUTH_TXN_COOKIE not in response.cookies or response.cookies.get(
        OAUTH_TXN_COOKIE
    ) in {None, ""}
    assert "code_verifier=" in provider_api.token_bodies[-1]
    assert "client_secret=google-secret" in provider_api.token_bodies[-1]

    me = client.get(
        f"{settings.API_V1_STR}/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me.status_code == 200
    body = me.json()
    assert body["email"] == "oauth-user@example.com"
    assert body["full_name"] == "OAuth User"
    assert body["has_password"] is False
    assert body["is_superuser"] is False

    db.expire_all()
    user = crud.get_user_by_email(session=db, email="oauth-user@example.com")
    assert user is not None
    assert user.hashed_password is None
    identity = db.exec(
        select(ExternalIdentity).where(ExternalIdentity.subject == "google-subject-1")
    ).one()
    assert identity.provider == "google"
    assert identity.identity_type == IdentityType.OIDC
    assert identity.user_id == user.id

    password_login = client.post(
        f"{settings.API_V1_STR}/login/access-token",
        data={"username": user.email, "password": "not-a-real-password"},
    )
    assert password_login.status_code == 400
    assert password_login.json()["detail"] == "Incorrect email or password"

    change = client.patch(
        f"{settings.API_V1_STR}/users/me/password",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "current_password": "not-a-real-password",
            "new_password": "new-password-1",
        },
    )
    assert change.status_code == 400
    assert (
        change.json()["detail"]
        == "This account has no password. Use password recovery to set one."
    )

    again = _callback(client, _authorize(client, "google")[0])
    assert again.status_code == 200
    db.expire_all()
    count = db.exec(
        select(func.count())
        .select_from(ExternalIdentity)
        .where(ExternalIdentity.subject == "google-subject-1")
    ).one()
    assert count == 1


@pytest.mark.usefixtures("oauth_settings")
def test_state_mismatch_and_missing_cookie(
    client: TestClient, provider_api: ProviderAPI
) -> None:
    state, _location = _authorize(client, "google")
    mismatch = _callback(client, state + "x")
    assert mismatch.status_code == 400
    assert mismatch.json()["detail"] == STATE_ERROR
    assert provider_api.token_bodies == []

    client.cookies.clear()
    missing = _callback(client, state)
    assert missing.status_code == 400
    assert missing.json()["detail"] == STATE_ERROR


@pytest.mark.usefixtures("oauth_settings")
def test_unverified_email_is_rejected(
    client: TestClient,
    db: Session,
    provider_api: ProviderAPI,
) -> None:
    provider_api.id_token = _id_token(
        email="unverified@example.com", email_verified=False, sub="unverified-sub"
    )
    response = _callback(client, _authorize(client, "google")[0])
    assert response.status_code == 400
    assert response.json()["detail"] == UNVERIFIED_EMAIL
    db.expire_all()
    assert crud.get_user_by_email(session=db, email="unverified@example.com") is None


@pytest.mark.usefixtures("oauth_settings")
def test_existing_user_is_linked(
    client: TestClient,
    db: Session,
    provider_api: ProviderAPI,
) -> None:
    email = "Existing.User@example.com"
    password = random_lower_string()
    user = crud.create_user(
        session=db, user_create=UserCreate(email=email, password=password)
    )
    provider_api.id_token = _id_token(
        email=email.lower(), sub="linked-subject", name="Ignored Name"
    )
    response = _callback(client, _authorize(client, "google")[0])
    assert response.status_code == 200
    token = response.json()["access_token"]
    me = client.get(
        f"{settings.API_V1_STR}/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me.status_code == 200
    assert me.json()["email"] == email
    assert me.json()["id"] == str(user.id)
    assert me.json()["has_password"] is True
    assert me.json()["full_name"] is None

    password_login = client.post(
        f"{settings.API_V1_STR}/login/access-token",
        data={"username": email, "password": password},
    )
    assert password_login.status_code == 200
    db.expire_all()
    identity = db.exec(
        select(ExternalIdentity).where(ExternalIdentity.subject == "linked-subject")
    ).one()
    assert identity.user_id == user.id
    assert identity.email == email.lower()


@pytest.mark.usefixtures("oauth_settings", "provider_api")
def test_github_login_uses_verified_primary_email(
    client: TestClient,
    db: Session,
) -> None:
    state, location = _authorize(client, "github")
    assert location.startswith("https://github.com/login/oauth/authorize?")
    assert parse_qs(urlparse(location).query)["scope"] == ["read:user user:email"]
    response = _callback(client, state)
    assert response.status_code == 200
    token = response.json()["access_token"]
    me = client.get(
        f"{settings.API_V1_STR}/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me.status_code == 200
    assert me.json()["email"] == "octo@example.com"
    assert me.json()["full_name"] == "Octo Cat"
    db.expire_all()
    identity = db.exec(
        select(ExternalIdentity).where(ExternalIdentity.provider == "github")
    ).one()
    assert identity.subject == "4242"
    assert identity.identity_type == IdentityType.OIDC


@pytest.mark.usefixtures("oauth_settings")
def test_github_unverified_email_is_rejected(
    client: TestClient, provider_api: ProviderAPI
) -> None:
    provider_api.github_emails = [
        {"email": "hidden@example.com", "primary": True, "verified": False}
    ]
    response = _callback(client, _authorize(client, "github")[0])
    assert response.status_code == 400
    assert response.json()["detail"] == UNVERIFIED_EMAIL


@pytest.mark.usefixtures("oauth_settings")
def test_inactive_linked_user_cannot_sign_in(
    client: TestClient,
    db: Session,
    provider_api: ProviderAPI,
) -> None:
    provider_api.id_token = _id_token(
        email="inactive-oauth@example.com", sub="inactive-sub"
    )
    first = _callback(client, _authorize(client, "google")[0])
    assert first.status_code == 200
    db.expire_all()
    user = db.exec(select(User).where(User.email == "inactive-oauth@example.com")).one()
    user.is_active = False
    db.add(user)
    db.commit()
    second = _callback(client, _authorize(client, "google")[0])
    assert second.status_code == 400
    assert second.json()["detail"] == "Inactive user"


@pytest.mark.usefixtures("oauth_settings")
def test_generic_oidc_provider(
    client: TestClient,
    db: Session,
    provider_api: ProviderAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "")
    monkeypatch.setattr(
        settings,
        "OIDC_PROVIDERS",
        json.dumps(
            [
                {
                    "id": "auth0",
                    "name": "Auth0",
                    "client_id": "google-client",
                    "client_secret": "auth0-secret",
                    "discovery_url": (
                        "https://auth.example.test/.well-known/openid-configuration"
                    ),
                }
            ]
        ),
    )
    provider_api.id_token = _id_token(
        iss="https://auth.example.test",
        aud="google-client",
        email="generic@example.com",
        sub="generic-sub",
    )
    response = _callback(client, _authorize(client, "auth0")[0])
    assert response.status_code == 200
    db.expire_all()
    identity = db.exec(
        select(ExternalIdentity).where(ExternalIdentity.subject == "generic-sub")
    ).one()
    assert identity.provider == "auth0"


@pytest.mark.usefixtures("oauth_settings")
def test_provider_rejects_code_and_bad_identity_token(
    client: TestClient, provider_api: ProviderAPI
) -> None:
    provider_api.token_payload = {"error": "invalid_grant"}
    rejected = _callback(client, _authorize(client, "google")[0])
    assert rejected.status_code == 400
    assert "rejected" in rejected.json()["detail"]

    provider_api.token_payload = {"access_token": "only-access"}
    missing_id = _callback(client, _authorize(client, "google")[0])
    assert missing_id.status_code == 400
    assert missing_id.json()["detail"] == (
        "Identity provider did not return an identity token"
    )

    provider_api.token_payload = None
    provider_api.id_token = jwt.encode({"sub": "x"}, "secret", algorithm="HS256")
    bad_alg = _callback(client, _authorize(client, "google")[0])
    assert bad_alg.status_code == 400
    assert bad_alg.json()["detail"] == "Unsupported identity token algorithm"

    provider_api.id_token = _id_token(
        email_verified="true", sub="string-verified", name="N" * 300
    )
    accepted = _callback(client, _authorize(client, "google")[0])
    assert accepted.status_code == 200


@pytest.mark.usefixtures("oauth_settings")
def test_disabled_provider_and_bad_configuration_are_rejected(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, provider_api: ProviderAPI
) -> None:
    state, _location = _authorize(client, "google")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "")
    disabled = _callback(client, state)
    assert disabled.status_code == 400
    assert disabled.json()["detail"] == "Unknown or disabled OAuth provider"

    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "google-client")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "google-secret")
    monkeypatch.setattr(settings, "OIDC_PROVIDERS", "")
    state, _location = _authorize(client, "google")
    monkeypatch.setattr(settings, "OIDC_PROVIDERS", '{"id": "google"}')
    invalid = _callback(client, state)
    assert invalid.status_code == 500
    authorize = client.get(
        f"{settings.API_V1_STR}/login/oauth/google/authorize",
        follow_redirects=False,
    )
    assert authorize.status_code == 500
    monkeypatch.setattr(settings, "OIDC_PROVIDERS", "[1]")
    not_object = client.get(f"{settings.API_V1_STR}/login/oauth/providers")
    assert not_object.status_code == 500

    monkeypatch.setattr(settings, "OIDC_PROVIDERS", "{}")
    not_list = client.get(f"{settings.API_V1_STR}/login/oauth/providers")
    assert not_list.status_code == 500
    assert not_list.json()["detail"] == "OIDC_PROVIDERS must be a JSON array"

    monkeypatch.setattr(
        settings,
        "OIDC_PROVIDERS",
        json.dumps(
            [
                {
                    "id": "google",
                    "name": "Duplicate",
                    "client_id": "x",
                    "client_secret": "y",
                    "discovery_url": "https://auth.example.test/.well-known/openid-configuration",
                }
            ]
        ),
    )
    duplicate = client.get(f"{settings.API_V1_STR}/login/oauth/providers")
    assert duplicate.status_code == 500

    monkeypatch.setattr(settings, "OIDC_PROVIDERS", "")
    provider_api.discovery_document = {"issuer": "https://issuer.example.test"}
    incomplete = client.get(
        f"{settings.API_V1_STR}/login/oauth/google/authorize",
        follow_redirects=False,
    )
    assert incomplete.status_code == 400
    assert "incomplete" in incomplete.json()["detail"]


@pytest.mark.usefixtures("oauth_settings")
def test_repeated_login_updates_provider_email(
    client: TestClient, db: Session, provider_api: ProviderAPI
) -> None:
    provider_api.id_token = _id_token(email="first@example.com", sub="email-change")
    assert _callback(client, _authorize(client, "google")[0]).status_code == 200
    provider_api.id_token = _id_token(email="second@example.com", sub="email-change")
    assert _callback(client, _authorize(client, "google")[0]).status_code == 200
    db.expire_all()
    identity = db.exec(
        select(ExternalIdentity).where(ExternalIdentity.subject == "email-change")
    ).one()
    assert identity.email == "second@example.com"
    user = db.get(User, identity.user_id)
    assert user is not None
    assert user.email == "first@example.com"


@pytest.mark.usefixtures("oauth_settings", "provider_api")
def test_github_falls_back_to_verified_email_and_login(
    client: TestClient, db: Session, provider_api: ProviderAPI
) -> None:
    provider_api.github_user = {"id": 99, "name": "  ", "login": "fallback-login"}
    provider_api.github_emails = [
        "not-a-dict",
        {"email": "secondary@example.com", "primary": False, "verified": True},
        {"email": "unverified@example.com", "primary": True, "verified": False},
    ]
    response = _callback(client, _authorize(client, "github")[0])
    assert response.status_code == 200
    db.expire_all()
    user = crud.get_user_by_email(session=db, email="secondary@example.com")
    assert user is not None
    assert user.full_name == "fallback-login"


@pytest.mark.usefixtures("oauth_settings")
def test_discovery_failure(client: TestClient, provider_api: ProviderAPI) -> None:
    provider_api.fail_discovery = True
    response = client.get(
        f"{settings.API_V1_STR}/login/oauth/google/authorize",
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Could not reach the identity provider"


def test_link_external_identity_survives_a_concurrent_insert(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    commits = {"count": 0}
    original_commit = db.commit

    def commit_then_conflict() -> None:
        commits["count"] += 1
        original_commit()
        if commits["count"] == 2:
            raise IntegrityError("INSERT", {}, Exception("duplicate subject"))

    monkeypatch.setattr(db, "commit", commit_then_conflict)
    user = crud.link_external_identity(
        session=db,
        identity_type=IdentityType.OIDC,
        provider="google",
        subject="race-subject",
        email=random_email(),
        full_name="Race",
    )
    assert user.id is not None
    db.expire_all()
    identity = db.exec(
        select(ExternalIdentity).where(ExternalIdentity.subject == "race-subject")
    ).one()
    assert identity.user_id == user.id


def test_link_external_identity_reraises_when_the_race_is_not_visible(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    commits = {"count": 0}
    original_commit = db.commit

    def conflict_before_identity_commit() -> None:
        commits["count"] += 1
        if commits["count"] == 2:
            raise IntegrityError("INSERT", {}, Exception("duplicate subject"))
        original_commit()

    monkeypatch.setattr(db, "commit", conflict_before_identity_commit)
    with pytest.raises(IntegrityError):
        crud.link_external_identity(
            session=db,
            identity_type=IdentityType.OIDC,
            provider="google",
            subject="hidden-race",
            email=random_email(),
            full_name=None,
        )
