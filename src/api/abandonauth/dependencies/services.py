from fastapi import HTTPException
from prisma.models import User
from starlette.status import HTTP_404_NOT_FOUND

from abandonauth.dependencies.auth.jwt import (
    decode_jwt,
    generate_long_lived_jwt,
)
from abandonauth.models.auth import JwtClaimsDataDto, JwtDto, ScopeEnum


BASE_URL = "http://localhost"


async def identify_user(user_id: str) -> User:
    """Get the user with the given ID or raise an HTTP 404."""
    user = await User.prisma().find_unique({
        "id": user_id,
    })

    if user is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    return user


def get_new_token(exchange_token: str, aud: str | None = None) -> JwtDto:
    """Return a short-term or long-term AbandonAuth JWT from an existing JWT."""
    token_data: JwtClaimsDataDto = decode_jwt(token=exchange_token, aud=aud, required_scope=ScopeEnum.identify)
    return JwtDto(token=generate_long_lived_jwt(token_data.user_id, token_data.aud))
