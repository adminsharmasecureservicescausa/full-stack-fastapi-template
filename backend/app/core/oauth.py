import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import urlencode

import httpx
import jwt
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    HttpUrl,
    TypeAdapter,
    ValidationError,
)

from app.core.config import settings
from app.core.security import ALGORITHM

OAUTH_TXN_COOKIE = "oauth_txn"
OAUTH_TXN_MINUTES = 10
OAUTH_REDIRECT_PATH = "/oauth/callback"
UNVERIFIED_EMAIL = "Email is missing or not verified by the identity provider"
STATE_ERROR = "Invalid or mismatched OAuth state"
_PROVIDER_ID = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_EMAIL_ADAPTER = TypeAdapter(EmailStr)


class OAuthError(Exception):
    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


class OAuthConfigError(OAuthError):
    """Raised when provider settings are present but invalid."""


@dataclass(frozen=True)
class OAuthProvider:
    id: str
    name: str
    client_id: str
    client_secret: str
    scopes: tuple[str, ...]
    profile: Literal["oidc", "github"]
    discovery_url: str | None = None
    authorize_url: str | None = None
    token_url: str | None = None


@dataclass(frozen=True)
class ExternalProfile:
    subject: str
    email: str
    full_name: str | None


class _ExtraOIDCProvider(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    client_id: str
    client_secret: str
    discovery_url: HttpUrl
    scopes: list[str] = ["openid", "email", "profile"]


def http_client() -> httpx.Client:
    return httpx.Client(timeout=10.0)


def oauth_redirect_uri() -> str:
    return f"{settings.FRONTEND_HOST.rstrip('/')}{OAUTH_REDIRECT_PATH}"


def cookie_secure() -> bool:
    return settings.FRONTEND_HOST.startswith("https://")


def generate_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def create_transaction_token(*, state: str, code_verifier: str, provider: str) -> str:
    expire = datetime.now(UTC) + timedelta(minutes=OAUTH_TXN_MINUTES)
    payload = {
        "exp": expire,
        "typ": "oauth_txn",
        "state": state,
        "cv": code_verifier,
        "provider": provider,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def read_transaction_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.InvalidTokenError:
        raise OAuthError(STATE_ERROR) from None
    if not isinstance(payload, dict) or payload.get("typ") != "oauth_txn":
        raise OAuthError(STATE_ERROR)
    state = payload.get("state")
    verifier = payload.get("cv")
    provider = payload.get("provider")
    if (
        not isinstance(state, str)
        or not isinstance(verifier, str)
        or not isinstance(provider, str)
    ):
        raise OAuthError(STATE_ERROR)
    return payload


def _enabled(client_id: str, client_secret: str) -> bool:
    return bool(client_id.strip() and client_secret.strip())


def _extra_providers() -> list[OAuthProvider]:
    raw = settings.OIDC_PROVIDERS.strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise OAuthConfigError("OIDC_PROVIDERS is not valid JSON") from None
    if not isinstance(parsed, list):
        raise OAuthConfigError("OIDC_PROVIDERS must be a JSON array")
    providers: list[OAuthProvider] = []
    seen = {"google", "github"}
    for item in parsed:
        try:
            spec = _ExtraOIDCProvider.model_validate(item)
        except ValidationError:
            raise OAuthConfigError(
                "OIDC_PROVIDERS contains an invalid provider"
            ) from None
        provider_id = spec.id.strip()
        if (
            not _PROVIDER_ID.fullmatch(provider_id)
            or provider_id in seen
            or not spec.name.strip()
            or not spec.client_id.strip()
            or not spec.client_secret.strip()
            or not spec.scopes
        ):
            raise OAuthConfigError("OIDC_PROVIDERS contains an invalid provider")
        seen.add(provider_id)
        providers.append(
            OAuthProvider(
                id=provider_id,
                name=spec.name.strip(),
                client_id=spec.client_id.strip(),
                client_secret=spec.client_secret.strip(),
                scopes=tuple(spec.scopes),
                profile="oidc",
                discovery_url=str(spec.discovery_url),
            )
        )
    return providers


def list_providers() -> list[OAuthProvider]:
    providers: list[OAuthProvider] = []
    if _enabled(settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET):
        providers.append(
            OAuthProvider(
                id="google",
                name="Google",
                client_id=settings.GOOGLE_CLIENT_ID.strip(),
                client_secret=settings.GOOGLE_CLIENT_SECRET.strip(),
                scopes=("openid", "email", "profile"),
                profile="oidc",
                discovery_url=(
                    "https://accounts.google.com/.well-known/openid-configuration"
                ),
            )
        )
    if _enabled(settings.GITHUB_CLIENT_ID, settings.GITHUB_CLIENT_SECRET):
        providers.append(
            OAuthProvider(
                id="github",
                name="GitHub",
                client_id=settings.GITHUB_CLIENT_ID.strip(),
                client_secret=settings.GITHUB_CLIENT_SECRET.strip(),
                scopes=("read:user", "user:email"),
                profile="github",
                authorize_url="https://github.com/login/oauth/authorize",
                token_url="https://github.com/login/oauth/access_token",
            )
        )
    providers.extend(_extra_providers())
    return providers


def get_provider(provider_id: str) -> OAuthProvider | None:
    for provider in list_providers():
        if provider.id == provider_id:
            return provider
    return None


def _request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
) -> Any:
    try:
        with http_client() as client:
            response = client.request(method, url, headers=headers, data=data)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError:
        raise OAuthError("Could not reach the identity provider") from None
    except ValueError:
        raise OAuthError("Unexpected response from the identity provider") from None


def _as_object_dict(payload: Any, message: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise OAuthError(message)
    return payload


def _discovery(provider: OAuthProvider) -> dict[str, Any]:
    if not provider.discovery_url:
        raise OAuthError("OIDC provider is missing a discovery document")
    document = _as_object_dict(
        _request_json("GET", provider.discovery_url),
        "Identity provider discovery document is incomplete",
    )
    for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not isinstance(document.get(key), str):
            raise OAuthError("Identity provider discovery document is incomplete")
    return document


def build_authorization_url(
    provider: OAuthProvider, *, state: str, code_challenge: str
) -> str:
    if provider.profile == "oidc":
        endpoint = _discovery(provider)["authorization_endpoint"]
    else:
        if not provider.authorize_url:
            raise OAuthError("OAuth provider is missing an authorization endpoint")
        endpoint = provider.authorize_url
    query = urlencode(
        {
            "client_id": provider.client_id,
            "redirect_uri": oauth_redirect_uri(),
            "response_type": "code",
            "scope": " ".join(provider.scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{query}"


def _exchange_code(
    provider: OAuthProvider, *, token_url: str, code: str, code_verifier: str
) -> dict[str, Any]:
    payload = _as_object_dict(
        _request_json(
            "POST",
            token_url,
            headers={"Accept": "application/json"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": oauth_redirect_uri(),
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
                "code_verifier": code_verifier,
            },
        ),
        "Unexpected token response from the identity provider",
    )
    if payload.get("error"):
        raise OAuthError("The identity provider rejected the authorization code")
    return payload


def _email_verified(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == "true"
    return False


def _normalize_email(email: str) -> str:
    try:
        return str(_EMAIL_ADAPTER.validate_python(email.strip().lower()))
    except ValidationError:
        raise OAuthError(UNVERIFIED_EMAIL) from None


def _normalize_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name:
        return None
    return name[:255]


def _require_subject(value: Any) -> str:
    subject = str(value).strip() if value is not None else ""
    if not subject or len(subject) > 255 or subject == "None":
        raise OAuthError("Identity provider subject is invalid")
    return subject


def _verify_id_token(
    provider: OAuthProvider, id_token: str, discovery: dict[str, Any]
) -> dict[str, Any]:
    jwks_uri = discovery["jwks_uri"]
    jwks = _as_object_dict(
        _request_json("GET", jwks_uri),
        "Identity provider signing keys are unavailable",
    )
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise OAuthError("Identity provider signing keys are unavailable")
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.InvalidTokenError:
        raise OAuthError("Identity token could not be verified") from None
    algorithm = header.get("alg")
    if algorithm not in {"RS256", "RS384", "RS512"}:
        raise OAuthError("Unsupported identity token algorithm")
    kid = header.get("kid")
    selected: dict[str, Any] | None = None
    for key in keys:
        if not isinstance(key, dict):
            continue
        if key.get("use") not in (None, "sig"):
            continue
        if kid is None or key.get("kid") == kid:
            selected = key
            if kid is not None:
                break
    if selected is None:
        raise OAuthError("Identity provider signing key was not found")
    try:
        signing_key = jwt.PyJWK.from_dict(selected).key
        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=[algorithm],
            audience=provider.client_id,
            issuer=discovery["issuer"],
        )
    except jwt.InvalidTokenError:
        raise OAuthError("Identity token could not be verified") from None
    if not isinstance(claims, dict):
        raise OAuthError("Identity token could not be verified")
    return claims


def _profile_from_oidc_claims(claims: dict[str, Any]) -> ExternalProfile:
    email = claims.get("email")
    if not isinstance(email, str) or not _email_verified(claims.get("email_verified")):
        raise OAuthError(UNVERIFIED_EMAIL)
    return ExternalProfile(
        subject=_require_subject(claims.get("sub")),
        email=_normalize_email(email),
        full_name=_normalize_name(claims.get("name")),
    )


def _github_email(access_token: str) -> str:
    payload = _request_json(
        "GET",
        "https://api.github.com/user/emails",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": settings.PROJECT_NAME,
        },
    )
    if not isinstance(payload, list):
        raise OAuthError(UNVERIFIED_EMAIL)
    verified: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        if item.get("verified") is True and isinstance(item.get("email"), str):
            verified.append(item)
    if not verified:
        raise OAuthError(UNVERIFIED_EMAIL)
    for item in verified:
        if item.get("primary") is True:
            return _normalize_email(item["email"])
    return _normalize_email(verified[0]["email"])


def _github_profile(
    provider: OAuthProvider, *, code: str, code_verifier: str
) -> ExternalProfile:
    if not provider.token_url:
        raise OAuthError("OAuth provider is missing a token endpoint")
    token = _exchange_code(
        provider,
        token_url=provider.token_url,
        code=code,
        code_verifier=code_verifier,
    )
    access_token = token.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise OAuthError("The identity provider rejected the authorization code")
    user = _as_object_dict(
        _request_json(
            "GET",
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": settings.PROJECT_NAME,
            },
        ),
        "Unexpected response from the identity provider",
    )
    email = _github_email(access_token)
    name = _normalize_name(user.get("name")) or _normalize_name(user.get("login"))
    return ExternalProfile(
        subject=_require_subject(user.get("id")),
        email=email,
        full_name=name,
    )


def fetch_profile(
    provider: OAuthProvider, *, code: str, code_verifier: str
) -> ExternalProfile:
    if provider.profile == "github":
        return _github_profile(provider, code=code, code_verifier=code_verifier)
    discovery = _discovery(provider)
    token = _exchange_code(
        provider,
        token_url=discovery["token_endpoint"],
        code=code,
        code_verifier=code_verifier,
    )
    id_token = token.get("id_token")
    if not isinstance(id_token, str):
        raise OAuthError("Identity provider did not return an identity token")
    claims = _verify_id_token(provider, id_token, discovery)
    return _profile_from_oidc_claims(claims)
