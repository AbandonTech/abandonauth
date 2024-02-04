from pydantic import BaseModel


class UserDto(BaseModel):
    """Contains sanitized user-safe data."""
    id: str
    username: str


class UserAuthInfo(BaseModel):
    """User info and authorization info"""
    id: str | None
    username: str | None
    token: str | None
