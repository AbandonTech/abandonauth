import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from prisma.models import DeveloperApplication
from starlette.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN

from abandonauth.models import DiscordLoginDto
from abandonauth.routers.discord import login_with_discord
from abandonauth.routers.github import login_with_github
from abandonauth.settings import settings

router = APIRouter(prefix="/ui")

BASE_URL = "http://localhost"


@router.get("/", include_in_schema=False)
async def index(request: Request, code: str | None = None) -> RedirectResponse:
    """Developer landing page for AbandonAuth UI."""
    if code:
        login_body = {
            "id": settings.ABANDON_AUTH_DEVELOPER_APP_ID,
            "refresh_token": settings.ABANDON_AUTH_DEVELOPER_APP_TOKEN,
        }

        login_headers = {
            "exchange-token": code,
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{BASE_URL}/login", headers=login_headers, json=login_body)

        # If login failed, set token to None so that the user will be redirected back to the login page
        token = None if resp.status_code != HTTP_200_OK else resp.json().get("token")
    else:
        token = request.cookies.get("Authorization")

    authenticated = False

    if token:
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {token}"}
            authenticated = (await client.get(f"{BASE_URL}/me", headers=headers)).status_code == HTTP_200_OK

    resp = RedirectResponse(settings.ABANDON_AUTH_SITE_URL)

    if authenticated is False:
        return resp

    resp.set_cookie(
        key="Authorization",
        value=token,  # pyright: ignore [reportArgumentType]
        domain=settings.ABANDON_AUTH_SITE_URL,
        httponly=True
    )

    return resp


@router.get("/discord-callback")
async def discord_callback(request: Request) -> RedirectResponse:
    """Discord callback endpoint for authenticating with Discord OAuth with AbandonAuth UI."""
    code = request.query_params.get("code")

    # Application ID and callback URI are verified before being added to the discord callback URI
    # The state param can be altered via user input on previous steps and must be verified here
    if request_state := request.query_params.get("state"):
        app_id, redirect_url = request_state.split(",")

        dev_app = await DeveloperApplication.prisma().find_unique(
            where={"id": app_id},
            include={"callback_uris": True},
        )

        # This check is very important. application ID and callback URI must be validated
        # The state in the discord login URL cannot be trusted
        if not dev_app or not dev_app.callback_uris or redirect_url not in [x.uri for x in dev_app.callback_uris]:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid application ID or callback_uri",
            )
    else:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="application_id and callback_uri are required in query param 'state'",
        )

    if code:
        login_data = DiscordLoginDto(code=code, redirect_uri=settings.ABANDON_AUTH_DISCORD_CALLBACK)
        exchange_token = (await login_with_discord(login_data, app_id)).token

        return RedirectResponse(f"{redirect_url}?code={exchange_token}")

    return RedirectResponse(redirect_url)


@router.get("/github-callback")
async def github_callback(request: Request) -> RedirectResponse:
    """GitHub callback endpoint for authenticating with GitHub OAuth with AbandonAuth UI."""
    code = request.query_params.get("code")

    # Application ID and callback URI are verified before being added to the discord callback URI
    # The state param can be altered via user input on previous steps and must be verified here
    if request_state := request.query_params.get("state"):
        app_id, redirect_url = request_state.split(",")

        dev_app = await DeveloperApplication.prisma().find_unique(
            where={"id": app_id},
            include={"callback_uris": True},
        )

        # This check is very important. application ID and callback URI must be validated
        # The state in the github login URL cannot be trusted
        if not dev_app or not dev_app.callback_uris or redirect_url not in [x.uri for x in dev_app.callback_uris]:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid application ID or callback_uri",
            )
    else:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="application_id and callback_uri are required in query param 'state'",
        )

    if code:
        exchange_token = (await login_with_github(code, app_id)).token

        return RedirectResponse(f"{redirect_url}?code={exchange_token}")

    return RedirectResponse(redirect_url)
