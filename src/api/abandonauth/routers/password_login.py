from fastapi import APIRouter, HTTPException, Response
from prisma.models import PasswordAccount, User
from starlette.status import HTTP_401_UNAUTHORIZED

from abandonauth.dependencies.auth.hash import (
    get_hashed_data,
    verify_data,
)
from abandonauth.dependencies.auth.jwt import generate_long_lived_jwt
from abandonauth.models import JwtDto
from abandonauth.models.user import PasswordAccountSchema, PasswordLoginDto, UserDto
from abandonauth.settings import settings

router = APIRouter(tags=["Password Accounts"])


@router.post("/create_test_user", summary="Creates User and PasswordAccount")
async def create_test_user(user_data: PasswordAccountSchema) -> UserDto:
    """Create the supplied test user."""
    user = await User.prisma().create({
        "username": user_data.username,
        "password_account": {
            "create": {
                "password": get_hashed_data(user_data.password),
            },
        },
    })
    return UserDto(id=user.id, username=user.username)


@router.post("/login_test_user", summary="Login using password")
async def login_test_user(user_data: PasswordLoginDto, res: Response) -> JwtDto:
    """Login as the given test user."""
    password_account = await PasswordAccount.prisma().find_first(
        where={
            "user_id": str(user_data.user_id),
        },
    )
    if password_account is None or not verify_data(user_data.password, password_account.password):
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    access_token = generate_long_lived_jwt(str(password_account.user_id), settings.ABANDON_AUTH_DEVELOPER_APP_ID)
    res.set_cookie("Authorization", access_token, secure=True, httponly=True)
    return JwtDto(token=access_token)
