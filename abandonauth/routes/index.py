from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from prisma.models import User
from starlette.status import HTTP_404_NOT_FOUND

from abandonauth.dependencies.auth.jwt import JWTBearer
from abandonauth.models import UserDto

router = APIRouter()


@router.get("/", summary="Redirect to docs", include_in_schema=False)
async def index() -> RedirectResponse:
    """Redirect to docs when going to root."""
    return RedirectResponse("/docs")


@router.get("/me", response_model=UserDto)
async def current_user_information(user_id: str = Depends(JWTBearer())) -> UserDto:
    """Get information about the user from a jwt token."""
    user = await User.prisma().find_unique({
        "id": user_id
    })

    if user is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    return UserDto(id=user.id, username=user.username)
