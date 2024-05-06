import httpx
from fastapi import Request, HTTPException
from starlette.status import HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND

from abandonauth.models.user import UserAuthInfo
from abandonauth.models.auth import JwtClaimsDataDto, JwtDto, ScopeEnum
from abandonauth.settings import settings
from abandonauth.dependencies.auth.jwt import (
    generate_long_lived_jwt,
    decode_jwt,
)
from prisma.models import User

BASE_URL = "http://localhost"


async def user_info_from_me_response(request: Request) -> UserAuthInfo | None:
    """Return the user's info auth info."""
    if token := request.cookies.get("Authorization"):
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {token}"}
            me_response = await client.get(f"{BASE_URL}/me", headers=headers)

        me_response_data = me_response.json()

        if me_response.status_code == 200:
            user_uuid = me_response_data.get("id")
            username = me_response_data.get("username")
        else:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="User ID and/or username was missing")

        if None in (user_uuid, username):
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="User ID and/or username was missing")

        return UserAuthInfo(
            id=user_uuid,
            username=username,
            token=token,
        )
    return None


async def build_abandon_auth_redirect_url() -> str:
    """Return the redirect URL to be used for auth."""
    callback_uri = "/ui"
    return f"/ui/login?application_id={settings.ABANDON_AUTH_DEVELOPER_APP_ID}&callback_uri={callback_uri}"


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
