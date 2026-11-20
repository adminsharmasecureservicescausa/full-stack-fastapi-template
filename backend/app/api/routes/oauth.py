import secrets
from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from app import crud
from app.api.deps import SessionDep
from app.core import security
from app.core.config import settings
from app.core.oauth import (
    OAUTH_TXN_COOKIE,
    OAUTH_TXN_MINUTES,
    STATE_ERROR,
    OAuthConfigError,
    OAuthError,
    build_authorization_url,
    cookie_secure,
    create_transaction_token,
    fetch_profile,
    generate_pkce,
    get_provider,
    list_providers,
    read_transaction_token,
)
from app.models import (
    IdentityType,
    OAuthCallback,
    OAuthProviderPublic,
    OAuthProvidersPublic,
    Token,
)

router = APIRouter(tags=["login"])


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(
        OAUTH_TXN_COOKIE,
        path="/",
        secure=cookie_secure(),
        samesite="lax",
        httponly=True,
    )


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=OAUTH_TXN_COOKIE,
        value=token,
        httponly=True,
        secure=cookie_secure(),
        samesite="lax",
        max_age=OAUTH_TXN_MINUTES * 60,
        path="/",
    )


def _failure(detail: str, status_code: int) -> JSONResponse:
    response = JSONResponse(status_code=status_code, content={"detail": detail})
    _clear_cookie(response)
    return response


@router.get("/login/oauth/providers", response_model=OAuthProvidersPublic)
def read_oauth_providers() -> OAuthProvidersPublic:
    """
    OAuth providers enabled by configuration.
    """
    try:
        providers = list_providers()
    except OAuthConfigError as exc:
        raise HTTPException(status_code=500, detail=exc.detail) from None
    return OAuthProvidersPublic(
        data=[
            OAuthProviderPublic(id=provider.id, name=provider.name)
            for provider in providers
        ]
    )


@router.get("/login/oauth/{provider}/authorize")
def oauth_authorize(provider: str) -> RedirectResponse:
    """
    Start the authorization-code flow with PKCE.
    """
    try:
        selected = get_provider(provider)
    except OAuthConfigError as exc:
        raise HTTPException(status_code=500, detail=exc.detail) from None
    if selected is None:
        raise HTTPException(
            status_code=404, detail="Unknown or disabled OAuth provider"
        )
    state = secrets.token_urlsafe(32)
    verifier, challenge = generate_pkce()
    try:
        url = build_authorization_url(selected, state=state, code_challenge=challenge)
    except OAuthError as exc:
        raise HTTPException(status_code=400, detail=exc.detail) from None
    response = RedirectResponse(url=url, status_code=302)
    _set_cookie(
        response,
        create_transaction_token(
            state=state, code_verifier=verifier, provider=selected.id
        ),
    )
    return response


@router.post("/login/oauth/callback", response_model=Token)
def oauth_callback(
    session: SessionDep, body: OAuthCallback, request: Request
) -> Response:
    """
    Exchange the authorization code and issue the application access token.
    """
    raw_token = request.cookies.get(OAUTH_TXN_COOKIE)
    if not raw_token:
        return _failure(STATE_ERROR, 400)
    try:
        transaction = read_transaction_token(raw_token)
        expected_state = transaction["state"]
        if not isinstance(expected_state, str) or not secrets.compare_digest(
            expected_state, body.state
        ):
            return _failure(STATE_ERROR, 400)
        provider_id = transaction["provider"]
        code_verifier = transaction["cv"]
        if not isinstance(provider_id, str) or not isinstance(code_verifier, str):
            return _failure(STATE_ERROR, 400)
        provider = get_provider(provider_id)
        if provider is None:
            return _failure("Unknown or disabled OAuth provider", 400)
        profile = fetch_profile(provider, code=body.code, code_verifier=code_verifier)
        user = crud.link_external_identity(
            session=session,
            identity_type=IdentityType.OIDC,
            provider=provider.id,
            subject=profile.subject,
            email=profile.email,
            full_name=profile.full_name,
        )
    except OAuthConfigError as exc:
        return _failure(exc.detail, 500)
    except (OAuthError, ValueError) as exc:
        detail = (
            exc.detail
            if isinstance(exc, OAuthError)
            else "Could not link the external identity"
        )
        return _failure(detail, 400)
    if not user.is_active:
        return _failure("Inactive user", 400)
    access_token = security.create_access_token(
        user.id, expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    response = JSONResponse(content=Token(access_token=access_token).model_dump())
    _clear_cookie(response)
    return response
