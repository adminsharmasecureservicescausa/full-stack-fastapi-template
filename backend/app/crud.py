import uuid
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, func, select

from app.core.security import get_password_hash, verify_password
from app.models import (
    ExternalIdentity,
    Item,
    ItemCreate,
    User,
    UserCreate,
    UserUpdate,
)


def create_user(*, session: Session, user_create: UserCreate) -> User:
    db_obj = User.model_validate(
        user_create, update={"hashed_password": get_password_hash(user_create.password)}
    )
    session.add(db_obj)
    session.commit()
    session.refresh(db_obj)
    return db_obj


def update_user(*, session: Session, db_user: User, user_in: UserUpdate) -> Any:
    user_data = user_in.model_dump(exclude_unset=True)
    extra_data = {}
    if user_data.get("password"):
        password = user_data["password"]
        hashed_password = get_password_hash(password)
        extra_data["hashed_password"] = hashed_password
    db_user.sqlmodel_update(user_data, update=extra_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


def get_user_by_email(*, session: Session, email: str) -> User | None:
    statement = select(User).where(User.email == email)
    session_user = session.exec(statement).first()
    return session_user


def get_user_by_email_insensitive(*, session: Session, email: str) -> User | None:
    statement = select(User).where(func.lower(User.email) == email.lower())
    return session.exec(statement).first()


def get_external_identity(
    *,
    session: Session,
    identity_type: str,
    provider: str,
    subject: str,
) -> ExternalIdentity | None:
    statement = select(ExternalIdentity).where(
        ExternalIdentity.identity_type == identity_type,
        ExternalIdentity.provider == provider,
        ExternalIdentity.subject == subject,
    )
    return session.exec(statement).first()


def link_external_identity(
    *,
    session: Session,
    identity_type: str,
    provider: str,
    subject: str,
    email: str,
    full_name: str | None,
) -> User:
    """Find or create the user for a verified external identity and link it.

    An existing ``(identity_type, provider, subject)`` link wins, including
    when the address at the provider has changed. Otherwise a user with the
    same email is reused. Otherwise a user without a password is created.
    """
    existing = get_external_identity(
        session=session,
        identity_type=identity_type,
        provider=provider,
        subject=subject,
    )
    if existing:
        user = session.get(User, existing.user_id)
        if user is None:
            raise ValueError("Linked user no longer exists")
        if existing.email != email:
            existing.email = email
            session.add(existing)
            session.commit()
        return user

    user = get_user_by_email_insensitive(session=session, email=email)
    created = False
    if user is None:
        user = User(email=email, full_name=full_name, hashed_password=None)
        session.add(user)
        session.commit()
        session.refresh(user)
        created = True

    identity = ExternalIdentity(
        user_id=user.id,
        identity_type=identity_type,
        provider=provider,
        subject=subject,
        email=email,
    )
    session.add(identity)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raced = get_external_identity(
            session=session,
            identity_type=identity_type,
            provider=provider,
            subject=subject,
        )
        if raced is None:
            if created:
                raise
            user = get_user_by_email_insensitive(session=session, email=email)
            if user is None:
                raise
            session.add(
                ExternalIdentity(
                    user_id=user.id,
                    identity_type=identity_type,
                    provider=provider,
                    subject=subject,
                    email=email,
                )
            )
            session.commit()
        else:
            linked = session.get(User, raced.user_id)
            if linked is None:
                raise ValueError("Linked user no longer exists") from None
            user = linked
    session.refresh(user)
    return user


# Dummy hash to use for timing attack prevention when user is not found
# This is an Argon2 hash of a random password, used to ensure constant-time comparison
DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$MjQyZWE1MzBjYjJlZTI0Yw$YTU4NGM5ZTZmYjE2NzZlZjY0ZWY3ZGRkY2U2OWFjNjk"


def authenticate(*, session: Session, email: str, password: str) -> User | None:
    db_user = get_user_by_email(session=session, email=email)
    if not db_user:
        # Prevent timing attacks by running password verification even when user doesn't exist
        # This ensures the response time is similar whether or not the email exists
        verify_password(password, DUMMY_HASH)
        return None
    if not db_user.hashed_password:
        # OAuth-only accounts have no password. Verify a dummy hash so the
        # response time matches a wrong password, then reject the login.
        verify_password(password, DUMMY_HASH)
        return None
    verified, updated_password_hash = verify_password(password, db_user.hashed_password)
    if not verified:
        return None
    if updated_password_hash:
        db_user.hashed_password = updated_password_hash
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
    return db_user


def create_item(*, session: Session, item_in: ItemCreate, owner_id: uuid.UUID) -> Item:
    db_item = Item.model_validate(item_in, update={"owner_id": owner_id})
    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item
