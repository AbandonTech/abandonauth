from uuid import UUID

from pydantic import BaseModel


class DeveloperApplicationDto(BaseModel):
    """Basic data for developer applications"""

    id: str
    owner_id: str


class DeveloperApplicationWithCallbackUriDto(DeveloperApplicationDto):
    """Basic data for developer applications as well as the Callback URIs for the app"""

    callback_uris: list[str]


class CreateDeveloperApplicationDto(DeveloperApplicationDto):
    """Basic info for a developer application as well as the refresh token."""

    token: str


class LoginDeveloperApplicationDto(BaseModel):
    """Data for logging in a developer application."""

    id: UUID
    refresh_token: str


class CreateCallbackUriDto(BaseModel):
    """Data for creating a callback URI"""
    developer_application_id: str
    uri: str


class CallbackUriDto(CreateCallbackUriDto):
    """All data that should be displayed to a user for a callback URI"""
    id: int
