import httpx
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from prisma.models import DeveloperApplication
from starlette.status import HTTP_403_FORBIDDEN, HTTP_400_BAD_REQUEST

from abandonauth import templates  # type: ignore

from abandonauth.models import DiscordLoginDto
from abandonauth.routers.discord import login_with_discord
from abandonauth.routers.index import get_new_token
from abandonauth.settings import settings

router = APIRouter(prefix="/ui")

jinja_templates = Jinja2Templates(directory=templates.__path__)

BASE_URL = "http://localhost"


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def developer_dashboard(request: Request):
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

    errors = []
    if not (application_id and callback_uri):
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Both application_id and callback_uri are required"
        )
    else:
        dev_app = await DeveloperApplication.prisma().find_unique(
            where={"id": application_id},
            include={"callback_uris": True}
        )

        # This check is a convenience in order to provide accurate and immediate feedback to users
        # The security check for application IDs and callback URIs must be done later in the auth flow
        if not dev_app or not dev_app.callback_uris or callback_uri not in [x.uri for x in dev_app.callback_uris]:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid application ID or callback_uri",
            )

    discord_login_url = f"{settings.ABANDON_AUTH_DISCORD_REDIRECT}&state={dev_app.id},{callback_uri}"

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

    # Application ID and callback URI are verified before being added to the discord callback URI
    # The state param can be altered via user input on previous steps and must be verified here
    if request_state := request.query_params.get("state"):
        app_id, redirect_url = request_state.split(",")

        dev_app = await DeveloperApplication.prisma().find_unique(
            where={"id": app_id},
            include={"callback_uris": True}
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
            detail="application_id and callback_uri are required in query param 'state'"
        )

    if code:
        login_data = DiscordLoginDto(code=code, redirect_uri=settings.ABANDON_AUTH_DISCORD_CALLBACK)
        exchange_token = (await login_with_discord(login_data, app_id)).token

        user_token = get_new_token(exchange_token).token

        resp = RedirectResponse(redirect_url)
        resp.set_cookie(key="Authorization", value=user_token)

        return resp

    return RedirectResponse(redirect_url)
