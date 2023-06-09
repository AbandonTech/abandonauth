from fastapi import APIRouter, Depends, Header

from abandonauth.dependencies.auth.jwt import JWTBearer, generate_long_lived_jwt
from abandonauth.dependencies.auth.refresh_token import generate_refresh_token, get_refresh_token_hash, verify_refresh_token
from abandonauth.models import CreateDeveloperApplicationDto, DeveloperApplicationDto, JwtDto
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
async def login_developer_application(authentication: str | None = Header(default=None)) -> JwtDto:
    """Authenticate a developer application given a long-term refresh token or raise a **401** response.
    
    Returns a short-lived access token for the developer application.
    """
    ...


@router.delete(
    "/{application_id}",
    response_model=DeveloperApplicationDto,
    summary="Delete the developer application with the given id",
    response_description="The deleted application data"
)
async def delete_org_server(application_id: int, user_id: str = Depends(JWTBearer())) -> DeveloperApplicationDto:
    ...


@router.get(
    "/me",
    response_description="General information about the authenticated developer application",
    response_model=DeveloperApplicationDto
)
async def current_developer_application_information(application_id: str = Depends(JWTBearer())) -> DeveloperApplicationDto:
    ...
