from uuid import UUID

from pydantic import BaseModel


class UserDto(BaseModel):
    """Contains sanitized user-safe data."""

    id: str
    username: str


class UserAuthInfo(BaseModel):
    """User info and authorization info."""

    id: str | None = None
    username: str | None = None
    token: str | None = None


class PasswordAccountSchema(BaseModel):
    """Data required to create User and PasswordAccount."""

    username: str
    password: str


class PasswordLoginDto(BaseModel):
    """Data required to login using password."""

    user_id: UUID
    password: str
