from fastapi import APIRouter, Depends
from fastapi.responses import RedirectResponse, Response
from prisma.models import User

from ..dependencies.auth import JWTBearer
from ..models import UserDto

router = APIRouter()


@router.get("/", include_in_schema=False)
async def index() -> Response:
    """Redirect to docs."""
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
