from pydantic import BaseModel


class DeveloperApplicationDto(BaseModel):
    """Basic data for developer applications"""

    id: str
    owner_id: str


class CreateDeveloperApplicationDto(DeveloperApplicationDto):
    """Basic info for a developer application as well as the refresh token."""

    token: str


class LoginDeveloperApplicationDto(BaseModel):
    """Data for logging in a developer application."""

    id: str
    refresh_token: str