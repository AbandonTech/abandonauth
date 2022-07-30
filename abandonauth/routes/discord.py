import requests
from classy_config import ConfigValue
from fastapi import APIRouter, HTTPException
from prisma.errors import UniqueViolationError
from prisma.models import User

from ..dependencies.auth import generate_jwt
from ..models import DetailDto, JwtDto

router = APIRouter(
    prefix="/discord",
    tags=["Discord"]
)

API_ENDPOINT = 'https://discord.com/api/v10'
CLIENT_ID = ConfigValue("DISCORD_CLIENT_ID", str)
CLIENT_SECRET = ConfigValue("DISCORD_CLIENT_SECRET", str)
CALLBACK_BASE = ConfigValue("DISCORD_CALLBACK_BASE", str)
REGISTER_CALLBACK_URL = f"{CALLBACK_BASE}/register"
LOGIN_CALLBACK_URL = f"{CALLBACK_BASE}/login"


def _html_button(callback_url: str, message: str) -> str:
    """Create a html button for usage on swagger docs."""
    return f"""
<a href="{API_ENDPOINT}/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={callback_url}&response_type=code&scope=identify">
    <button>{message}</button>
</a>
"""  # noqa: E501


@router.get(
    "/register",
    response_model=DetailDto,
    description=_html_button(
        REGISTER_CALLBACK_URL,
        "Register with discord",
    )
)
async def register_with_discord(code: str) -> DetailDto:
    """Create an account using Discord's OAuth2."""
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REGISTER_CALLBACK_URL
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    r = requests.post(
        '%s/oauth2/token' % API_ENDPOINT, data=data, headers=headers)

    if r.status_code != 200:
        raise HTTPException(
            status_code=400,
            detail="Unexpected error communicating with Discord")

    token = r.json()["access_token"]

    r = requests.get(
        '%s/users/@me' % API_ENDPOINT,
        headers={"Authorization": f"Bearer {token}"})

    user = r.json()

    try:
        await User.prisma().create({
            "id": 1,
            "username": user["username"],
            "discord_account": {
                "create": {
                    "id": int(user["id"])
                }
            }
        })
    except UniqueViolationError:
        raise HTTPException(
            status_code=409,
            detail="Discord account already tied to an account")

    return DetailDto(
        detail="Registration successful! "
               "You can now login with your Discord account."
    )


@router.get(
    "/login",
    response_model=JwtDto,
    description=_html_button(
        LOGIN_CALLBACK_URL,
        "Login with discord",
    )
)
async def login_with_discord(code: str) -> JwtDto:
    """Log a user in using Discord's OAuth2 as validation."""
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': LOGIN_CALLBACK_URL
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    r = requests.post(
        '%s/oauth2/token' % API_ENDPOINT, data=data, headers=headers)
    r.raise_for_status()

    token = r.json()["access_token"]

    r = requests.get(
        '%s/users/@me' % API_ENDPOINT,
        headers={"Authorization": f"Bearer {token}"})

    user = r.json()

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
