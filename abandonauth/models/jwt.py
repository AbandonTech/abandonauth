from pydantic import BaseModel


class JwtDto(BaseModel):
    """Contains jwt token data to be sent to a client."""

    token: str
