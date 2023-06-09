from fastapi import APIRouter, Depends, HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_404_NOT_FOUND

from abandonauth.dependencies.auth.jwt import JWTBearer, generate_short_lived_jwt
from abandonauth.dependencies.auth.refresh_token import (
    generate_refresh_token,
    get_refresh_token_hash,
    verify_refresh_token
)
from abandonauth.models import (
    CreateDeveloperApplicationDto,
    DeveloperApplicationDto,
    JwtDto,
    LoginDeveloperApplicationDto
)
from prisma.models import DeveloperApplication

router = APIRouter(
    prefix="/developer_application",
    tags=["Developer Applications"]
)


@router.post(
    "",
    summary="Create a new developer application and retrieve a refresh token. This token will never be visible again.",
    response_description="The refresh token for the new developer account.",
    response_model=CreateDeveloperApplicationDto
)
async def create_developer_application(user_id: str = Depends(JWTBearer())) -> CreateDeveloperApplicationDto:
    """Create a new developer application owned by the currently authenticated User.

    Returns the permanent refresh token for the account. This token can only be manually changed.
    """
    refresh_token = generate_refresh_token()
    hashed_token = get_refresh_token_hash(refresh_token)

    dev_app = await DeveloperApplication.prisma().create({
        "owner_id": user_id,
        "refresh_token": hashed_token
    })

    return CreateDeveloperApplicationDto(id=dev_app.id, owner_id=dev_app.owner_id, token=refresh_token)


@router.post(
    "/login",
    summary="Exchange a developer application refresh token for a short-lived AbandonAuth JWT",
    response_description="A short-lived JWT to authenticate a developer application",
    response_model=JwtDto
)
async def login_developer_application(login_data: LoginDeveloperApplicationDto) -> JwtDto:
    """Authenticate a developer application given a long-term refresh token or raise a **401** response.

    Returns a short-lived exchange token for the developer application.
    """
    dev_app = await DeveloperApplication.prisma().find_unique(
        {
            "id": login_data.id
        }
    )

    if not dev_app or not verify_refresh_token(login_data.refresh_token, dev_app.refresh_token):
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid username or refresh token",
        )

    return JwtDto(token=generate_short_lived_jwt(dev_app.id))


@router.delete(
    "/{application_id}",
    summary="Delete the developer application with the given id",
    response_description="The deleted application data",
    response_model=DeveloperApplicationDto
)
async def delete_developer_application(
        application_id: str,
        user_id: str = Depends(JWTBearer())
) -> DeveloperApplicationDto:
    """Delete the given developer application if the current user owns the application."""
    dev_app = await DeveloperApplication.prisma().find_unique({
        "id": application_id
    })

    if dev_app and user_id == dev_app.owner_id:
        deleted = await DeveloperApplication.prisma().delete({
            "id": dev_app.id
        })

        # It should not be possible for this condition to fail. Adding for Pyright
        if deleted:
            return DeveloperApplicationDto(id=deleted.id, owner_id=deleted.owner_id)

    raise HTTPException(status_code=HTTP_404_NOT_FOUND)


@router.patch(
    "/{application_id}",
    summary="Change the refresh token on a developer application. This is not reversible.",
    response_description="The newly generated refresh token for the application.",
    response_model=CreateDeveloperApplicationDto
)
async def change_application_refresh_token(
        application_id: str,
        user_id: str = Depends(JWTBearer())
) -> CreateDeveloperApplicationDto:
    """Generates and sets a new refresh token for the given developer application.

    This action is not reversible and destroys the existing refresh token for the application.
    """
    dev_app = await DeveloperApplication.prisma().find_unique({
        "id": application_id
    })

    if dev_app and user_id == dev_app.owner_id:
        refresh_token = generate_refresh_token()
        hashed_token = get_refresh_token_hash(refresh_token)

        updated = await DeveloperApplication.prisma().update(
            where={
                "id": dev_app.id
            },
            data={
                "refresh_token": hashed_token
            }
        )

        # It should not be possible for this condition to fail. Adding for Pyright
        if updated:
            return CreateDeveloperApplicationDto(id=updated.id, owner_id=updated.owner_id, token=refresh_token)

    raise HTTPException(status_code=HTTP_404_NOT_FOUND)


@router.get(
    "/me",
    summary="Verify and retrieve information for a developer application",
    response_description="General information about the authenticated developer application",
    response_model=DeveloperApplicationDto
)
async def current_developer_application_information(
        application_id: str = Depends(JWTBearer())
) -> DeveloperApplicationDto:
    """Get information about the developer application from a jwt."""
    dev_app = await DeveloperApplication.prisma().find_unique({
        "id": application_id
    })

    if dev_app is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    return DeveloperApplicationDto(id=dev_app.id, owner_id=dev_app.owner_id)
