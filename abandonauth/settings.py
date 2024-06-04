import pydantic
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings are loaded from .env."""

    DATABASE_URL: pydantic.SecretStr

    JWT_SECRET: pydantic.SecretStr
    JWT_HASHING_ALGO: str
    JWT_EXPIRES_IN_SECONDS_LONG_LIVED: int
    JWT_EXPIRES_IN_SECONDS_SHORT_LIVED: int

    ABANDON_AUTH_DEVELOPER_APP_ID: str
    ABANDON_AUTH_DEVELOPER_APP_TOKEN: str

    ABANDON_AUTH_DISCORD_REDIRECT: str
    ABANDON_AUTH_DISCORD_CALLBACK: str
    DISCORD_CLIENT_ID: str
    DISCORD_CLIENT_SECRET: pydantic.SecretStr

    ABANDON_AUTH_GITHUB_CALLBACK: str
    ABANDON_AUTH_GITHUB_REDIRECT: str
    GITHUB_CLIENT_ID: str
    GITHUB_CLIENT_SECRET: pydantic.SecretStr

    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: pydantic.SecretStr
    GOOGLE_CALLBACK: str
    DEBUG: bool

    model_config = SettingsConfigDict(frozen=True, env_file=".env", env_file_encoding="utf-8")


settings = Settings()  # pyright: ignore [reportCallIssue]
