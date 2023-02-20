import pydantic
from pydantic import BaseSettings


class Settings(BaseSettings):
    """Settings are loaded from .env"""

    DATABASE_URL: pydantic.SecretStr

    JWT_SECRET: pydantic.SecretStr
    JWT_HASHING_ALGO: str
    JWT_EXPIRES_IN_SECONDS: int

    BASE_URL: str
    DISCORD_CLIENT_ID: str
    DISCORD_CLIENT_SECRET: pydantic.SecretStr
    DISCORD_CALLBACK_BASE: str

    class Config:
        frozen = True
        env_file = '.env'
        env_file_encoding = 'utf-8'


settings = Settings()  # pyright: ignore
