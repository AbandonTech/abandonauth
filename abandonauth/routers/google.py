import httpx
from fastapi import APIRouter
from starlette.responses import RedirectResponse

from abandonauth.dependencies.auth.jwt import generate_short_lived_jwt
from abandonauth.models import JwtDto
from abandonauth.settings import settings
from prisma.models import User

router = APIRouter(
    prefix="/google",
    tags=["Google"],
)


@router.get("", response_model=JwtDto)
async def login_with_google(code: str, state: str) -> RedirectResponse:
    """Log a user in using Google's OAuth2 as validation."""
    data = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_CALLBACK,
        "client_secret": settings.GOOGLE_CLIENT_SECRET.get_secret_value(),
        "grant_type": "authorization_code",
        "code": code,
    }

    headers = {"Accept": "application/json"}
    async with httpx.AsyncClient(headers=headers) as client:
        response = await client.post("https://oauth2.googleapis.com/token", data=data)

        response.raise_for_status()

        token = response.json()["access_token"]

        response = await client.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {token}"},
        )

        response.raise_for_status()
        google_user = response.json()

    user = await User.prisma().find_first(
        where={
            "google_account": {
                "is": {
                    "id": google_user["sub"],
                },
            },
        },
    )

    if user is None:
        user = await User.prisma().create({
            "username": google_user["name"],
            "google_account": {
                "create": {
                    "id": google_user["sub"],
                },
            },
        })

    return RedirectResponse(f"{state}?authentication={generate_short_lived_jwt(user.id, 'fake_application_id')}")
