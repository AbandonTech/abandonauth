from fastapi import APIRouter, Depends
from prisma.models import User

from ..dependencies.auth import JWTBearer
from ..models import UserDto

router = APIRouter()


@router.get("/me", response_model=UserDto)
async def current_user_information(
    user_id: int = Depends(JWTBearer())
) -> UserDto:
    """Get information about the user from a jwt token."""
    user = await User.prisma().find_unique({
        "id": user_id
    })

    return UserDto(id=user.id, username=user.username)
