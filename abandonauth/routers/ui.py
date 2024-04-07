from typing import Annotated
from uuid import UUID

import httpx
from fastapi import APIRouter, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_403_FORBIDDEN, HTTP_400_BAD_REQUEST, HTTP_303_SEE_OTHER, HTTP_404_NOT_FOUND

from abandonauth import templates  # type: ignore
from abandonauth.models import DiscordLoginDto, DeveloperApplicationWithCallbackUriDto
from abandonauth.routers.discord import login_with_discord
from abandonauth.settings import settings
from dependencies.services import build_abandon_auth_redirect_url, user_info_from_me_response
from prisma.models import DeveloperApplication

router = APIRouter(prefix="/ui")

jinja_templates = Jinja2Templates(directory=templates.__path__)

BASE_URL = "http://localhost"


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request, code: str | None = None):
    """Developer landing page for AbandonAuth UI."""
    if code:
        login_body = {
            "id": settings.ABANDON_AUTH_DEVELOPER_APP_ID,
            "refresh_token": settings.ABANDON_AUTH_DEVELOPER_APP_TOKEN
        }

        login_headers = {
            "exchange-token": code
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{BASE_URL}/login", headers=login_headers, json=login_body)

        # If login failed, set token to None so that the user will be redirected back to the logic page
        if resp.status_code != 200:
            token = None
        else:
            token = resp.json().get("token")
    else:
        token = request.cookies.get("Authorization")

    authenticated = False

    if token:
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {token}"}
            authenticated = (await client.get(f"{BASE_URL}/me", headers=headers)).status_code == 200

    if authenticated is False:
        return RedirectResponse(await build_abandon_auth_redirect_url())

    resp = RedirectResponse("/ui/developer_dashboard")
    resp.set_cookie(key="Authorization", value=token)  # pyright: ignore

    return resp


@router.get("/developer_dashboard", response_class=HTMLResponse, include_in_schema=False)
async def developer_dashboard(request: Request):
    """Developer dashboard page for AbandonAuth UI."""
    user_info = await user_info_from_me_response(request)

    if user_info is None:
        return RedirectResponse(f"/ui/login?application_id={settings.ABANDON_AUTH_DEVELOPER_APP_ID}&callback_uri=/ui")

    return jinja_templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "authenticated": user_info.token is not None,
            "username": user_info.username,
            "user_id": user_info.id
        }
    )


@router.get("/applications/new", response_class=HTMLResponse, include_in_schema=False)
async def create_new_developer_application_form(request: Request):
    """Page for managing developer applications"""
    user_info = await user_info_from_me_response(request)

    if user_info is None:
        return RedirectResponse(await build_abandon_auth_redirect_url())

    return jinja_templates.TemplateResponse(
        "create_developer_app.html",
        {
            "request": request,
            "authenticated": user_info.token is not None
        }
    )


@router.post("/applications/new", response_class=HTMLResponse, include_in_schema=False)
async def create_new_developer_applications(request: Request):
    """Page for managing developer applications"""
    user_info = await user_info_from_me_response(request)

    if user_info is None:
        return RedirectResponse(await build_abandon_auth_redirect_url())

    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {user_info.token}"}
        new_dev_app = (await client.post(f"{BASE_URL}/developer_application", headers=headers)).json()

    return jinja_templates.TemplateResponse(
        "created_application_info.html",
        {
            "request": request,
            "dev_app_id": new_dev_app.get("id"),
            "dev_app_token": new_dev_app.get("token"),
            "authenticated": user_info.token is not None

        }
    )


@router.get("/applications", response_class=HTMLResponse, include_in_schema=False)
async def list_developer_applications(request: Request):
    """Page for managing developer applications"""
    user_info = await user_info_from_me_response(request)

    if user_info is None:
        return RedirectResponse(await build_abandon_auth_redirect_url())

    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {user_info.token}"}
        dev_apps = (await client.get(f"{BASE_URL}/user/applications", headers=headers)).json()

    return jinja_templates.TemplateResponse(
        "developer_apps.html",
        {
            "request": request,
            "dev_apps": [x["id"] for x in dev_apps],
            "authenticated": user_info.token is not None
        }
    )


@router.get("/applications/{application_id}", response_class=HTMLResponse, include_in_schema=False)
async def developer_application_detail(
        request: Request,
        application_id: str
):
    """Page for managing developer applications"""
    user_info = await user_info_from_me_response(request)

    if user_info is None:
        return RedirectResponse(await build_abandon_auth_redirect_url())

    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {user_info.token}"}
        application_info = (
            await client.get(f"{BASE_URL}/developer_application/{application_id}", headers=headers)
        ).json()

    app_dto = DeveloperApplicationWithCallbackUriDto(**application_info)

    return jinja_templates.TemplateResponse(
        "developer_app_info.html",
        {
            "request": request,
            "dev_app_id": app_dto.id,
            "owner_id": app_dto.owner_id,
            "callback_uris": app_dto.callback_uris,
            "authenticated": user_info.token is not None
        }
    )


@router.get("/applications/{application_id}/reset_token", response_class=HTMLResponse, include_in_schema=False)
async def reset_dev_application_token_confirmation(request: Request, application_id: str):
    """Request for resetting a developer application token from the dev application info page."""
    user_info = await user_info_from_me_response(request)

    if user_info is None:
        return RedirectResponse(await build_abandon_auth_redirect_url())

    return jinja_templates.TemplateResponse(
        "reset_dev_app_token_confirmation.html",
        {
            "request": request,
            "dev_app_id": application_id,
            "authenticated": user_info.token is not None
        }
    )


@router.post("/applications/{application_id}/reset_token", response_class=HTMLResponse, include_in_schema=False)
async def reset_dev_application_token(request: Request, application_id: str):
    """Request for resetting a developer application token from the dev application info page."""
    user_info = await user_info_from_me_response(request)

    if user_info is None:
        return RedirectResponse(await build_abandon_auth_redirect_url())

    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {user_info.token}"}
        application_info = (
            await client.patch(f"{BASE_URL}/developer_application/{application_id}/reset_token", headers=headers)
        ).json()

    return jinja_templates.TemplateResponse(
        "created_application_info.html",
        {
            "request": request,
            "dev_app_id": application_info.get("id"),
            "dev_app_token": application_info.get("token"),
            "authenticated": user_info.token is not None
        }
    )


@router.get("/applications/{application_id}/delete_application", response_class=HTMLResponse, include_in_schema=False)
async def delete_dev_application_confirmation(request: Request, application_id: str):
    """Request for deleting a developer application."""
    user_info = await user_info_from_me_response(request)

    if user_info is None:
        return RedirectResponse(await build_abandon_auth_redirect_url())

    return jinja_templates.TemplateResponse(
        "delete_dev_app_confirmation.html",
        {
            "request": request,
            "dev_app_id": application_id,
            "authenticated": user_info.token is not None,
        }
    )


@router.post("/applications/{application_id}/delete_application", response_class=HTMLResponse, include_in_schema=False)
async def delete_dev_application(request: Request, application_id: str):
    """Request for deleting a developer application."""
    user_info = await user_info_from_me_response(request)

    if user_info is None:
        return RedirectResponse(await build_abandon_auth_redirect_url())

    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {user_info.token}"}
        await client.delete(f"{BASE_URL}/developer_application/{application_id}", headers=headers)

    return RedirectResponse("/ui/applications", status_code=HTTP_303_SEE_OTHER)


@router.get("/applications/{application_id}/edit_callback_uris", response_class=HTMLResponse, include_in_schema=False)
async def edit_dev_application_callback_uris_page(request: Request, application_id: str):
    """Page for editing a developer application's callback URIs."""
    user_info = await user_info_from_me_response(request)

    if user_info is None:
        return RedirectResponse(await build_abandon_auth_redirect_url())

    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {user_info.token}"}
        application_info = (
            await client.get(f"{BASE_URL}/developer_application/{application_id}", headers=headers)
        ).json()

    app_dto = DeveloperApplicationWithCallbackUriDto(**application_info)

    return jinja_templates.TemplateResponse(
        "edit_callback_uris.html",
        {
            "request": request,
            "dev_app_id": app_dto.id,
            "callback_uris": app_dto.callback_uris,
            "callback_uris_form_value": ",".join(app_dto.callback_uris),
            "authenticated": user_info.token is not None
        }
    )


@router.post("/applications/{application_id}/edit_callback_uris", response_class=HTMLResponse, include_in_schema=False)
async def edit_dev_application_callback_uris(
        request: Request,
        application_id: str,
        new_callback_uris: Annotated[str, Form()]
):
    """Request for deleting a developer application."""
    user_info = await user_info_from_me_response(request)

    if user_info is None:
        return RedirectResponse(await build_abandon_auth_redirect_url())

    formatted_uris = new_callback_uris.strip(" ").split(",")

    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {user_info.token}"}
        await client.patch(
            f"{BASE_URL}/developer_application/{application_id}/callback_uris",
            headers=headers,
            json=formatted_uris
        )

    return RedirectResponse(f"/ui/applications/{application_id}", status_code=HTTP_303_SEE_OTHER)


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def oauth_login(request: Request, application_id: UUID | None = None, callback_uri: str | None = None):
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
            where={"id": str(application_id)},
            include={"callback_uris": True}
        )

        # This check is a convenience in order to provide accurate and immediate feedback to users
        # The security check for application IDs and callback URIs must be done later in the auth flow
        if not dev_app:
            raise HTTPException(
                status_code=HTTP_404_NOT_FOUND,
                detail="Invalid application ID",
            )
        if not dev_app.callback_uris or callback_uri not in [x.uri for x in dev_app.callback_uris]:
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

        resp = RedirectResponse(f"{redirect_url}?code={exchange_token}")

        return resp

    return RedirectResponse(redirect_url)
