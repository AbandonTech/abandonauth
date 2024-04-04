from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, Header
from fastapi.responses import RedirectResponse
from prisma.models import User
from starlette.status import HTTP_404_NOT_FOUND, HTTP_401_UNAUTHORIZED

from abandonauth.dependencies.auth.developer_application_deps import LoginDevAppWithOptionalCredentialsDep
from abandonauth.dependencies.auth.jwt import (
    valid_token_cache,
    generate_long_lived_jwt,
    JWTBearer,
    decode_jwt,
    OptionalDeveloperAppJwtBearer
)
from abandonauth.models import JwtDto, DeveloperApplicationDto, UserDto
from prisma.models import DeveloperApplication

from abandonauth.models.auth import JwtClaimsDataDto, ScopeEnum

router = APIRouter()


async def identify_user(user_id: str) -> User:
    """Get the user with the given ID or raise an HTTP 404"""
    user = await User.prisma().find_unique({
        "id": user_id
    })

    if user is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    return user


def get_new_token(exchange_token: str, aud: str | None = None) -> JwtDto:
    """Return a short-term or long-term AbandonAuth JWT from an existing JWT."""
    token_data: JwtClaimsDataDto = decode_jwt(token=exchange_token, aud=aud, required_scope=ScopeEnum.identify)
    return JwtDto(token=generate_long_lived_jwt(token_data.user_id, token_data.aud))


@router.get("/", summary="Redirect to landing page", include_in_schema=False)
async def index() -> RedirectResponse:
    """Redirect to landing page when going to root."""
    return RedirectResponse("/ui")


@router.get(
    "/user/applications",
    summary="List all developer applications owned by the current user.",
    response_description="List of developer applications",
    response_model=list[DeveloperApplicationDto]
)
async def get_user_applications(
        token_data: JwtClaimsDataDto = Depends(JWTBearer())
) -> list[DeveloperApplicationDto]:
    """List all developer applications owned by the authenticated user."""
    dev_apps = await DeveloperApplication.prisma().find_many(
        where={
            "owner_id": token_data.user_id
        }
    )

    return [DeveloperApplicationDto(id=x.id, owner_id=x.owner_id) for x in dev_apps]


@router.get("/me", response_model=UserDto)
async def current_user_information(
        token_data: JwtClaimsDataDto = Depends(JWTBearer(scope=ScopeEnum.identify))
) -> UserDto:
    """Get information about the user from a jwt token."""
    user = await identify_user(token_data.user_id)

    return UserDto(id=user.id, username=user.username)


@router.post(
    "/login",
    summary="Exchange a temporary AbandonAuth token for a permanent user token.",
    response_description="A long-lived JWT to authenticate the user on AbandonAuth.",
    response_model=JwtDto
)
async def login_user(
        authenticated_dev_app: LoginDevAppWithOptionalCredentialsDep,
        dev_app_token: Annotated[JwtClaimsDataDto | None, Depends(OptionalDeveloperAppJwtBearer())],
        exchange_token: str = Header(),
) -> JwtDto:
    """Logs in a user using a short-term or long-term AbandonAuth JWT.

    New JWT's aud must match the developer application's ID as an additional security check.
    """
    if dev_app_token is not None:
        app_id = dev_app_token.user_id
    elif authenticated_dev_app is not None:
        app_id = authenticated_dev_app.id
    else:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Either a developer application JWT must be given in headers "
                   "or the developer application credentials must be passed in the request body"
        )
    return get_new_token(exchange_token, app_id)


@router.post("/burn-token", status_code=200)
async def burn_jwt(token: JwtDto):
    """
    Invalidate the given JWT.

    Attempts to delete the given token. Returns 200 response regardless of if the token existed.
    """
    try:
        valid_token_cache.remove(token.token)
    except KeyError:
        pass

    return Response(status_code=200)
