import httpx
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from prisma.models import DeveloperApplication
from starlette.status import HTTP_403_FORBIDDEN, HTTP_400_BAD_REQUEST

from abandonauth import templates  # type: ignore

from abandonauth.models import DiscordLoginDto
from abandonauth.routers.discord import login_with_discord
from abandonauth.settings import settings

router = APIRouter(prefix="/ui")

jinja_templates = Jinja2Templates(directory=templates.__path__)

BASE_URL = "http://localhost"


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request):
    """Developer landing page for AbandonAuth UI."""
    internal_app_id = settings.ABANDON_AUTH_DEVELOPER_APP_ID

    if token := request.cookies.get("Authorization"):
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {token}"}
            authenticated = (await client.get(f"{BASE_URL}/me", headers=headers)).status_code == 200
    else:
        authenticated = False

    if authenticated is False:
        return RedirectResponse(f"/ui/login?application_id={internal_app_id}&callback_uri=/ui")

    return jinja_templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "authenticated": authenticated
        }
    )


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def oauth_login(request: Request, application_id: str | None = None, callback_uri: str | None = None):
    """Login for initiating the OAuth flow

    This page is used to start the OAuth flow for applications using AbandonAuth.
    Users are redirected to the selected identity provider then directed to the specified, verified callback uri.
    Callback URL is validated as being valid for the given application ID.
    """

    errors = ["test"]
    if not (application_id and callback_uri):
        errors.append("Request url is invalid, login cannot be completed")
    else:
        dev_app = await DeveloperApplication.prisma().find_unique(
            where={"id": application_id},
            include={"callback_uris": True}
        )

        if not dev_app:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid application ID or callback_uri",
            )

        if dev_app.callback_uris:
            valid_callback_uris = [x.uri for x in dev_app.callback_uris]
        else:
            valid_callback_uris = []

        if callback_uri not in valid_callback_uris:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid application ID or callback_uri",
            )

    discord_login_url = f"{settings.ABANDON_AUTH_DISCORD_REDIRECT}&state={callback_uri}"

    return jinja_templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "discord_redirect": discord_login_url,
            "errors": errors
        }
    )


@router.get("/discord-callback", response_class=RedirectResponse)
async def discord_callback(request: Request) -> RedirectResponse:
    """Discord callback endpoint for authenticating with Discord OAuth with AbandonAuth UI."""
    code = request.query_params.get("code")

    redirect_url = request.query_params.get("state")

    if redirect_url is None:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Missing 'state' in query parameters, cannot determine redirect URL"
        )

    if code:
        login_data = DiscordLoginDto(code=code, redirect_uri=settings.ABANDON_AUTH_DISCORD_CALLBACK)
        exchange_token = (await login_with_discord(login_data)).token

        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {exchange_token}"}
            user_token = (await client.get(f"{BASE_URL}/login", headers=headers)).json().get("token")

        resp = RedirectResponse(redirect_url)
        resp.set_cookie(key="Authorization", value=user_token)

        return resp

    return RedirectResponse(redirect_url)
