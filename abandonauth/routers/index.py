import contextlib
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Header, Response
from fastapi.responses import RedirectResponse
from starlette.status import HTTP_401_UNAUTHORIZED

from abandonauth.dependencies.auth.developer_application_deps import LoginDevAppWithOptionalCredentialsDep
from abandonauth.dependencies.auth.jwt import (
    JWTBearer,
    OptionalDeveloperAppJwtBearer,
    valid_token_cache,
)
from abandonauth.dependencies.services import get_new_token, identify_user
from abandonauth.models import DeveloperApplicationDto, JwtDto, UserDto
from abandonauth.models.auth import JwtClaimsDataDto, ScopeEnum
from prisma.models import DeveloperApplication

router = APIRouter()


@router.get("/", summary="Redirect to landing page", include_in_schema=False)
async def index() -> RedirectResponse:
    """Redirect to landing page when going to root."""
    return RedirectResponse("/ui")


@router.get(
    "/user/applications",
    summary="List all developer applications owned by the current user.",
    response_description="List of developer applications",
    response_model=list[DeveloperApplicationDto],
)
async def get_user_applications(
        token_data: JwtClaimsDataDto = Depends(JWTBearer()),
) -> list[DeveloperApplicationDto]:
    """List all developer applications owned by the authenticated user."""
    dev_apps = await DeveloperApplication.prisma().find_many(
        where={
            "owner_id": token_data.user_id,
        },
    )

    return [DeveloperApplicationDto(id=x.id, owner_id=x.owner_id) for x in dev_apps]


@router.get("/me", response_model=UserDto)
async def current_user_information(
        token_data: JwtClaimsDataDto = Depends(JWTBearer(scope=ScopeEnum.identify)),
) -> UserDto:
    """Get information about the user from a jwt token."""
    user = await identify_user(token_data.user_id)

    return UserDto(id=user.id, username=user.username)


@router.post(
    "/login",
    summary="Exchange a temporary AbandonAuth token for a permanent user token.",
    response_description="A long-lived JWT to authenticate the user on AbandonAuth.",
    response_model=JwtDto,
)
async def login_user(
        authenticated_dev_app: LoginDevAppWithOptionalCredentialsDep,
        dev_app_token: Annotated[JwtClaimsDataDto | None, Depends(OptionalDeveloperAppJwtBearer())],
        exchange_token: Annotated[str, Header()],
) -> JwtDto:
    """
    Log in the user, using a short-term or long-term AbandonAuth JWT.

    New JWT's aud must match the developer application's ID as an additional security check.
    """
    if dev_app_token is not None:
        app_id = dev_app_token.user_id
    elif authenticated_dev_app is not None:
        app_id = str(authenticated_dev_app.id)
    else:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Either a developer application JWT must be given in headers "
                   "or the developer application credentials must be passed in the request body",
        )
    return get_new_token(exchange_token, app_id)


@router.post("/burn-token", status_code=200)
async def burn_jwt(token: JwtDto) -> Response:
    """
    Invalidate the given JWT.

    Attempts to delete the given token. Returns 200 response regardless of if the token existed.
    """
    with contextlib.suppress(KeyError):
        valid_token_cache.remove(token.token)

    return Response(status_code=200)
