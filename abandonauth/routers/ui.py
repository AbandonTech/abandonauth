import httpx
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from abandonauth import templates  # type: ignore

from abandonauth.models import DiscordLoginDto
from abandonauth.routers.discord import login_with_discord
from abandonauth.settings import settings

router = APIRouter(prefix="/ui")

jinja_templates = Jinja2Templates(directory=templates.__path__)

BASE_URL = "http://localhost"


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request):
    """Landing page for AbandonAuth UI."""
    if token := request.cookies.get("Authorization"):
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {token}"}
            authenticated = (await client.get(f"{BASE_URL}/me", headers=headers)).status_code == 200
    else:
        authenticated = False

    return jinja_templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "discord_redirect": settings.ABANDON_AUTH_DISCORD_REDIRECT,
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

    return jinja_templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "errors": errors
        }
    )


@router.get("/discord-callback", response_class=RedirectResponse)
async def discord_callback(request: Request) -> RedirectResponse:
    """Discord callback endpoint for authenticating with Discord OAuth with AbandonAuth UI."""
    code = request.query_params.get("code")

    if code:
        login_data = DiscordLoginDto(code=code, redirect_uri=settings.ABANDON_AUTH_DISCORD_CALLBACK)
        exchange_token = (await login_with_discord(login_data)).token

        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {exchange_token}"}
            user_token = (await client.get(f"{BASE_URL}/login", headers=headers)).json().get("token")

        resp = RedirectResponse("/ui")
        resp.set_cookie(key="Authorization", value=user_token)

        return resp

    return RedirectResponse("/ui")
