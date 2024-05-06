import httpx
from fastapi import APIRouter
from starlette.responses import RedirectResponse

from abandonauth.dependencies.auth.jwt import generate_short_lived_jwt
from abandonauth.models import JwtDto
from abandonauth.settings import settings
from prisma.models import User

router = APIRouter(
    prefix="/github",
    tags=["GitHub"],
)


@router.get("", response_model=JwtDto)
async def login_with_github(code: str, state: str) -> RedirectResponse:
    """Log a user in using GitHubs's OAuth2 as validation."""
    data = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": settings.GITHUB_CALLBACK,
        "client_secret": settings.GITHUB_CLIENT_SECRET.get_secret_value(),
        "code": code,
    }

    headers = {"Accept": "application/json"}
    async with httpx.AsyncClient(headers=headers) as client:
        response = await client.post("https://github.com/login/oauth/access_token", data=data)
        response.raise_for_status()

        token = response.json()["access_token"]

        response = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {token}"},
        )

        response.raise_for_status()
        github_user = response.json()

    user = await User.prisma().find_first(
        where={
            "github_account": {
                "is": {
                    "id": int(github_user["id"]),
                },
            },
        },
    )

    if user is None:
        user = await User.prisma().create({
            "username": github_user["login"],
            "github_account": {
                "create": {
                    "id": int(github_user["id"]),
                },
            },
        })

    return RedirectResponse(f"{state}?authentication={generate_short_lived_jwt(user.id, 'fake_application_id')}")
