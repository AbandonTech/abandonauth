from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import RedirectResponse
from prisma.models import User
from starlette.status import HTTP_404_NOT_FOUND

from abandonauth.dependencies.auth.jwt import valid_token_cache, generate_long_lived_jwt, JWTBearer
from abandonauth.models import JwtDto, DeveloperApplicationDto, UserDto
from prisma.models import DeveloperApplication

router = APIRouter()


async def identify_user(user_id: str) -> User:
    """Get the user with the given ID or raise an HTTP 404"""
    user = await User.prisma().find_unique({
        "id": user_id
    })

    if user is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    return user


@router.get("/", summary="Redirect to docs", include_in_schema=False)
async def index() -> RedirectResponse:
    """Redirect to docs when going to root."""
    return RedirectResponse("/ui")


@router.get(
    "/user/applications",
    summary="List all developer applications owned by the current user.",
    response_description="List of developer applications",
    response_model=list[DeveloperApplicationDto]
)
async def get_user_applications(user_id: str = Depends(JWTBearer())) -> list[DeveloperApplicationDto]:
    """List all developer applications owned by the authenticated user."""
    dev_apps = await DeveloperApplication.prisma().find_many(
        where={
            "owner_id": user_id
        }
    )

    return [DeveloperApplicationDto(id=x.id, owner_id=x.owner_id) for x in dev_apps]


@router.get("/me", response_model=UserDto)
async def current_user_information(user_id: str = Depends(JWTBearer())) -> UserDto:
    """Get information about the user from a jwt token."""
    user = await identify_user(user_id)

    return UserDto(id=user.id, username=user.username)


@router.get(
    "/login",
    summary="Exchange a temporary AbandonAuth token for a permanent user token.",
    response_description="A long-lived JWT to authenticate the user on AbandonAuth.",
    response_model=JwtDto
)
async def login_user(user_id: str = Depends(JWTBearer())) -> JwtDto:
    """Logs in a user using a short-term or long-term AbandonAuth JWT."""
    return JwtDto(token=generate_long_lived_jwt(user_id))


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
