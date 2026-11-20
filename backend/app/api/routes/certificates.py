import uuid
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app import crud
from app.api.deps import CurrentUser, SessionDep, get_current_active_superuser
from app.core import mtls, security
from app.core.config import settings
from app.core.mtls import MtlsError, VerifiedCertificate
from app.models import (
    CertificateLoginPublic,
    ClientCertificateCreate,
    ClientCertificatePublic,
    ClientCertificatesPublic,
    ExternalIdentity,
    IdentityType,
    Message,
    Token,
    User,
)

login_router = APIRouter(tags=["login"])
router = APIRouter(prefix="/users", tags=["users"])


def _http_error(exc: MtlsError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


def _require_feature() -> None:
    try:
        mtls.require_ready()
    except MtlsError as exc:
        raise _http_error(exc) from None


def _presented(request: Request) -> VerifiedCertificate:
    host = request.client.host if request.client else None
    header_name = settings.MTLS_CLIENT_CERT_HEADER.strip() or (
        "X-Forwarded-Tls-Client-Cert"
    )
    try:
        return mtls.verified_certificate_from_request(
            host, request.headers.get(header_name)
        )
    except MtlsError as exc:
        raise _http_error(exc) from None


def _public(identity: ExternalIdentity) -> ClientCertificatePublic:
    return ClientCertificatePublic(
        id=identity.id,
        fingerprint=identity.subject,
        email=identity.email,
        provider=identity.provider,
        created_at=identity.created_at,
    )


def _provider() -> str:
    return settings.MTLS_PROVIDER.strip()


def _link(
    session: SessionDep,
    user_id: uuid.UUID,
    verified: VerifiedCertificate,
    *,
    preferred_email: str | None = None,
) -> ExternalIdentity:
    email = verified.emails[0] if verified.emails else None
    if preferred_email and preferred_email.lower() in verified.emails:
        email = preferred_email.lower()
    try:
        return crud.link_certificate_identity(
            session=session,
            user_id=user_id,
            provider=_provider(),
            fingerprint=verified.fingerprint,
            email=email,
        )
    except crud.IdentityLinkError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None


def _users_for_certificate_emails(
    session: SessionDep, emails: tuple[str, ...]
) -> list[User]:
    matched: list[User] = []
    seen: set[uuid.UUID] = set()
    for email in emails:
        user = crud.get_user_by_email_insensitive(session=session, email=email)
        if user is None or user.id in seen:
            continue
        seen.add(user.id)
        matched.append(user)
    return matched


def _user_for_login(session: SessionDep, verified: VerifiedCertificate) -> User:
    existing = crud.get_external_identity(
        session=session,
        identity_type=IdentityType.MTLS,
        provider=_provider(),
        subject=verified.fingerprint,
    )
    if existing is not None:
        user = session.get(User, existing.user_id)
        if user is None:
            raise HTTPException(status_code=400, detail="Unknown certificate")
        return user
    if not settings.MTLS_MATCH_EMAIL:
        raise HTTPException(status_code=400, detail="Unknown certificate")
    matched = _users_for_certificate_emails(session, verified.emails)
    if not matched:
        raise HTTPException(status_code=400, detail="Unknown certificate")
    if len(matched) > 1:
        raise HTTPException(
            status_code=400,
            detail="Certificate email matches more than one account",
        )
    user = matched[0]
    _link(session, user.id, verified, preferred_email=user.email)
    return user


@login_router.get("/login/certificate", response_model=CertificateLoginPublic)
def read_certificate_login() -> CertificateLoginPublic:
    """
    Whether client-certificate sign-in is enabled and fully configured.
    """
    return CertificateLoginPublic(enabled=mtls.certificate_login_ready())


@login_router.post("/login/certificate", response_model=Token)
def login_with_certificate(session: SessionDep, request: Request) -> Token:
    """
    Issue an access token for the user linked to the presented client certificate.
    """
    _require_feature()
    user = _user_for_login(session, _presented(request))
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return Token(
        access_token=security.create_access_token(user.id, expires_delta=expires)
    )


@router.get("/me/certificates", response_model=ClientCertificatesPublic)
def read_my_certificates(session: SessionDep, current_user: CurrentUser) -> Any:
    """
    List client certificates linked to the current user.
    """
    identities = crud.list_certificate_identities(
        session=session, user_id=current_user.id
    )
    return ClientCertificatesPublic(
        data=[_public(identity) for identity in identities],
        count=len(identities),
    )


@router.post("/me/certificates", response_model=ClientCertificatePublic)
def link_certificate_pem(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    body: ClientCertificateCreate,
) -> Any:
    """
    Link an uploaded public certificate whose email matches this account.
    """
    _require_feature()
    try:
        verified = mtls.verify_uploaded_pem(body.pem)
    except MtlsError as exc:
        raise _http_error(exc) from None
    if current_user.email.lower() not in verified.emails:
        if not verified.emails:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Certificate has no email address. Present it in the browser "
                    "and link that certificate instead."
                ),
            )
        raise HTTPException(
            status_code=400,
            detail="Certificate email does not match this account",
        )
    identity = _link(
        session, current_user.id, verified, preferred_email=current_user.email
    )
    return _public(identity)


@router.post("/me/certificates/current", response_model=ClientCertificatePublic)
def link_presented_certificate(
    session: SessionDep, current_user: CurrentUser, request: Request
) -> Any:
    """
    Link the client certificate the trusted proxy presented on this request.
    """
    _require_feature()
    identity = _link(
        session,
        current_user.id,
        _presented(request),
        preferred_email=current_user.email,
    )
    return _public(identity)


@router.delete("/me/certificates/{certificate_id}", response_model=Message)
def unlink_my_certificate(
    session: SessionDep, current_user: CurrentUser, certificate_id: uuid.UUID
) -> Message:
    """
    Unlink one of the current user's client certificates.
    """
    deleted = crud.delete_certificate_identity(
        session=session, user_id=current_user.id, identity_id=certificate_id
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return Message(message="Certificate unlinked")


@router.get(
    "/{user_id}/certificates",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=ClientCertificatesPublic,
)
def read_user_certificates(session: SessionDep, user_id: uuid.UUID) -> Any:
    """
    List a user's client certificates.
    """
    if session.get(User, user_id) is None:
        raise HTTPException(status_code=404, detail="User not found")
    identities = crud.list_certificate_identities(session=session, user_id=user_id)
    return ClientCertificatesPublic(
        data=[_public(identity) for identity in identities],
        count=len(identities),
    )


@router.delete(
    "/{user_id}/certificates/{certificate_id}",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=Message,
)
def revoke_user_certificate(
    session: SessionDep, user_id: uuid.UUID, certificate_id: uuid.UUID
) -> Message:
    """
    Revoke a user's client certificate.
    """
    if session.get(User, user_id) is None:
        raise HTTPException(status_code=404, detail="User not found")
    deleted = crud.delete_certificate_identity(
        session=session, user_id=user_id, identity_id=certificate_id
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return Message(message="Certificate revoked")
