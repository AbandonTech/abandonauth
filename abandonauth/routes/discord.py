import httpx
from fastapi import APIRouter, HTTPException
from prisma.models import User
from starlette.status import HTTP_400_BAD_REQUEST

from abandonauth.dependencies.auth.jwt import generate_jwt
from abandonauth.models import JwtDto
from abandonauth.settings import settings

router = APIRouter(
    prefix="/discord",
    tags=["Discord"]
)

API_ENDPOINT = "https://discord.com/api/v10"


@router.get("", response_model=JwtDto)
async def login_with_discord(code: str, redirect_url: str) -> JwtDto:
    """Log a user in using Discord's OAuth2 as validation."""
    data = {
        "client_id": settings.DISCORD_CLIENT_ID,
        "client_secret": settings.DISCORD_CLIENT_SECRET.get_secret_value(),
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_url
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient(headers=headers) as client:
        response = await client.post(f"{API_ENDPOINT}/oauth2/token", data=data)
        response.raise_for_status()

        token = response.json()["access_token"]

        response = await client.get(f"{API_ENDPOINT}/users/@me", headers={
            "Authorization": f"Bearer {token}"})

        user = response.json()

    user = await User.prisma().find_first(
        where={
            "discord_account": {
                "is": {
                    "id": int(user["id"])
                }
            }
        }
    )

    if user is None:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Discord account is not tied to any accounts."
        )

    return JwtDto(token=generate_jwt(user.id))
