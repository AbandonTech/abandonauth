import httpx
from classy_config import ConfigValue
from fastapi import APIRouter, HTTPException
from prisma.models import User

from ..dependencies.auth import generate_jwt
from ..models import JwtDto

router = APIRouter(
    prefix="/discord",
    tags=["Discord"]
)

API_ENDPOINT = "https://discord.com/api/v10"
CLIENT_ID = ConfigValue("DISCORD_CLIENT_ID", str)
CLIENT_SECRET = ConfigValue("DISCORD_CLIENT_SECRET", str)


@router.get("", response_model=JwtDto)
async def login_with_discord(code: str, redirect_url: str) -> JwtDto:
    """Log a user in using Discord's OAuth2 as validation."""
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_url
    }

    async with httpx.AsyncClient(headers={
        "Content-Type": "application/x-www-form-urlencoded"}) as client:
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
            status_code=400,
            detail="Discord account is not tied to any accounts.")

    return JwtDto(token=generate_jwt(user.id))
