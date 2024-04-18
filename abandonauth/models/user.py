from uuid import UUID

from pydantic import BaseModel


class UserDto(BaseModel):
    """Contains sanitized user-safe data."""
    id: str
    username: str


class UserAuthInfo(BaseModel):
    """User info and authorization info"""
    id: str | None = None
    username: str | None = None
    token: str | None = None


class TestUserSchema(BaseModel):
    username: str
    password: str


class LoginTestUserSchema(BaseModel):
    user_id: UUID
    password: str
