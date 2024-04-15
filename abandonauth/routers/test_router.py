from abandonauth.settings import settings
from abandonauth.dependencies.auth.jwt import generate_long_lived_jwt
from fastapi import APIRouter, Response

from abandonauth.dependencies.auth.refresh_token import (
    generate_refresh_token,
    get_refresh_token_hash
)
from abandonauth.dependencies.auth.password import get_password_hash
from prisma.models import TestUser, User
from models.user import LoginTestUserSchema, TestUserSchema

router = APIRouter()


@router.post('/create_test_user', summary='Creates TestUser')
async def create_test_user(user: TestUserSchema):
    token = generate_refresh_token()
    test_user = await TestUser.prisma().create({
        "username": user.username,
        "password": get_password_hash(user.password),
        "refresh_token": get_refresh_token_hash(token)
    })

    await User.prisma().create({
        "id": test_user.id,
        "username": test_user.username
    })
    return {'user_id': test_user.id}


@router.post('/login_test_user', summary='Login TestUser')
async def login_test_user(user: LoginTestUserSchema, res: Response):
    await TestUser.prisma().find_unique(where={
        "id": str(user.user_id),
    })
    access_token = generate_long_lived_jwt(str(user.user_id), settings.ABANDON_AUTH_DEVELOPER_APP_ID)
    res.set_cookie('Authorization', access_token, secure=True, httponly=True)
    return {'access_token': access_token}
