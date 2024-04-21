from abandonauth.settings import settings
from abandonauth.dependencies.auth.jwt import generate_long_lived_jwt
from fastapi import APIRouter, Response

from abandonauth.dependencies.auth.hash import (
    get_hashed_data, verify_data
)
from prisma.models import PasswordAccount, User
from abandonauth.models.user import PasswordAccountSchema, PasswordLoginDto

router = APIRouter()


@router.post('/create_test_user', summary='Creates User and PasswordAccount')
async def create_test_user(user_data: PasswordAccountSchema):
    user = await User.prisma().find_first(
        where={
            "password_account": {
                "is": {
                    "password": get_hashed_data(user_data.password)
                }
            }
        }
    )

    if user is None:
        user = await User.prisma().create({
            "username": user_data.username,
            "password_account": {
                "create": {
                    "password": get_hashed_data(user_data.password)
                }
            }
        })
    return {'user_id': user.id}


@router.post('/login_test_user', summary='Login using password')
async def login_test_user(user_data: PasswordLoginDto, res: Response):
    password_account = await PasswordAccount.prisma().find_first(
        where={
            "user_id": str(user_data.user_id)
        }
    )
    if password_account is None:
        return {'message': 'User not found'}
    if not verify_data(user_data.password, password_account.password):
        return {'message': 'Invalid password'}
    access_token = generate_long_lived_jwt(str(password_account.user_id), settings.ABANDON_AUTH_DEVELOPER_APP_ID)
    res.set_cookie('Authorization', access_token, secure=True, httponly=True)
    return {'access_token': access_token}
