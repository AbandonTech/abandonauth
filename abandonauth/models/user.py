from pydantic import BaseModel


class UserDto(BaseModel):
    """Contains sanitized user-safe data."""

    id: str
    username: str
