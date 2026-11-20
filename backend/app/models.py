import uuid
from datetime import UTC, datetime

from pydantic import EmailStr, computed_field
from sqlalchemy import UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel


def get_datetime_utc() -> datetime:
    return datetime.now(UTC)


# Shared properties
class UserBase(SQLModel):
    email: EmailStr = Field(unique=True, index=True, max_length=255)
    is_active: bool = True
    is_superuser: bool = False
    full_name: str | None = Field(default=None, max_length=255)


# Properties to receive via API on creation
class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=128)


class UserRegister(SQLModel):
    email: EmailStr = Field(max_length=255)
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)


# Properties to receive via API on update, all are optional
class UserUpdate(SQLModel):
    email: EmailStr | None = Field(default=None, max_length=255)
    is_active: bool | None = None
    is_superuser: bool | None = None
    full_name: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, min_length=8, max_length=128)


class UserUpdateMe(SQLModel):
    full_name: str | None = Field(default=None, max_length=255)
    email: EmailStr | None = Field(default=None, max_length=255)


class UpdatePassword(SQLModel):
    current_password: str = Field(min_length=8, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


# Database model, database table inferred from class name
class User(UserBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    # Null when the account can only sign in with an external identity.
    hashed_password: str | None = Field(default=None)
    created_at: datetime | None = Field(default_factory=get_datetime_utc)
    items: list[Item] = Relationship(back_populates="owner", cascade_delete=True)
    external_identities: list[ExternalIdentity] = Relationship(
        back_populates="user", cascade_delete=True
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_password(self) -> bool:
        return self.hashed_password is not None


class IdentityType:
    """Authenticator families stored on ``ExternalIdentity``.

    ``oidc`` covers OpenID Connect and OAuth 2.0 providers. ``mtls`` is
    client-certificate login: ``provider`` is the trust-domain slug
    (``MTLS_PROVIDER``) and ``subject`` is the SHA-256 fingerprint of the
    certificate. New families reuse this table, so they do not need a
    migration.
    """

    OIDC = "oidc"
    MTLS = "mtls"


class ExternalIdentity(SQLModel, table=True):
    """A non-password login linked to a user.

    The unique key is ``(identity_type, provider, subject)``. For OIDC,
    ``provider`` is the IdP slug and ``subject`` is the provider's stable
    subject. For mutual TLS, ``provider`` is the configured trust domain and
    ``subject`` is the lowercase hex SHA-256 fingerprint.
    """

    __tablename__ = "external_identity"
    __table_args__ = (
        UniqueConstraint(
            "identity_type",
            "provider",
            "subject",
            name="uq_external_identity_subject",
        ),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(
        foreign_key="user.id", nullable=False, ondelete="CASCADE", index=True
    )
    identity_type: str = Field(max_length=32)
    provider: str = Field(max_length=64)
    subject: str = Field(max_length=255)
    email: str | None = Field(default=None, max_length=255)
    created_at: datetime | None = Field(default_factory=get_datetime_utc)
    user: User | None = Relationship(back_populates="external_identities")


# Properties to return via API, id is always required
class UserPublic(UserBase):
    id: uuid.UUID
    created_at: datetime | None = None
    has_password: bool = False


class UsersPublic(SQLModel):
    data: list[UserPublic]
    count: int


# Shared properties
class ItemBase(SQLModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=255)


# Properties to receive on item creation
class ItemCreate(ItemBase):
    pass


# Properties to receive on item update
class ItemUpdate(SQLModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=255)


# Database model, database table inferred from class name
class Item(ItemBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime | None = Field(default_factory=get_datetime_utc)
    owner_id: uuid.UUID = Field(
        foreign_key="user.id", nullable=False, ondelete="CASCADE"
    )
    owner: User | None = Relationship(back_populates="items")


# Properties to return via API, id is always required
class ItemPublic(ItemBase):
    id: uuid.UUID
    owner_id: uuid.UUID
    created_at: datetime | None = None


class ItemsPublic(SQLModel):
    data: list[ItemPublic]
    count: int


# Generic message
class Message(SQLModel):
    message: str


# JSON payload containing access token
class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"


# Contents of JWT token
class TokenPayload(SQLModel):
    sub: str | None = None


class NewPassword(SQLModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)


class OAuthProviderPublic(SQLModel):
    id: str
    name: str


class OAuthProvidersPublic(SQLModel):
    data: list[OAuthProviderPublic]


class OAuthCallback(SQLModel):
    code: str = Field(min_length=1, max_length=2048)
    state: str = Field(min_length=1, max_length=512)


class CertificateLoginPublic(SQLModel):
    enabled: bool


class ClientCertificatePublic(SQLModel):
    id: uuid.UUID
    fingerprint: str
    email: str | None = None
    provider: str
    created_at: datetime | None = None


class ClientCertificatesPublic(SQLModel):
    data: list[ClientCertificatePublic]
    count: int


class ClientCertificateCreate(SQLModel):
    pem: str = Field(min_length=1, max_length=20000)
