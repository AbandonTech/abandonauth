from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class JwtDto(BaseModel):
    """Contains jwt token data to be sent to a client."""

    token: str


class ScopeEnum(StrEnum):
    """All accepted scopes for an abandonauth JWT."""

    identify = "identify"
    abandonauth = "abandonauth"
    none = ""


class LifespanEnum(StrEnum):
    """Allowed lifespans for an abandonauth JWT."""

    long = "long"
    short = "short"


class JwtClaimsDataDto(BaseModel):
    """All claim data for an Abandon Auth JWT."""

    user_id: str
    exp: datetime
    scope: str
    aud: str
    lifespan: LifespanEnum
