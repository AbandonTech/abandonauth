from pydantic import BaseModel


class DiscordLoginDto(BaseModel):
    """Data required to login via Discord OAuth"""
    code: str
