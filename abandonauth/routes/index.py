from abandonauth.dependencies.auth import JWTBearer
from abandonauth.models import UserDto
from fastapi import APIRouter, Depends
from fastapi.responses import RedirectResponse
from prisma.models import User

router = APIRouter()


@router.get("/", summary="Redirect to docs", include_in_schema=False)
async def index() -> RedirectResponse:
    """Redirect to docs when going to root."""
    return RedirectResponse("/docs")


@router.get("/me", response_model=UserDto)
async def current_user_information(
    user_id: int = Depends(JWTBearer())
) -> UserDto:
    """Get information about the user from a jwt token."""
    user = await User.prisma().find_unique({
        "id": user_id
    })

    return UserDto(id=user.id, username=user.username)
