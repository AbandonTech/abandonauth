from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class JwtDto(BaseModel):
    """Contains jwt token data to be sent to a client."""

    token: str


class ScopeEnum(str, Enum):
    identify = "identify"
    abandonauth = "abandonauth"
    none = None


class LifespanEnum(str, Enum):
    long = "long"
    short = "short"


class JwtClaimsDataDto(BaseModel):
    """All claim data for an Abandon Auth JWT"""

    user_id: str
    exp: datetime
    scope: str
    aud: str
    lifespan: LifespanEnum
