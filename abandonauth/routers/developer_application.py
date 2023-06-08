from fastapi import APIRouter, Depends, Header

from abandonauth.dependencies.auth.jwt import JWTBearer, generate_temp_jwt
from abandonauth.models import DeveloperApplicationDto, JwtDto

router = APIRouter(
    prefix="/developer_application",
    tags=["Developer Applications"]
)

@router.post(
    "",
    summary="Create a new developer application",
    response_description="The refresh token for the new developer account", 
    response_model=JwtDto
)
async def create_developer_application(user_id: str = Depends(JWTBearer())) -> JwtDto:
    """Create a new developer application owned by the currently authenticated User.

    Returns the permanent refresh token for the account. This token can only be manually changed.
    """
    ...

@router.post(
    "/login",
    response_description="A long-lived JWT to authenticate a developer application",
    response_model=JwtDto
)
async def login_developer_application(authentication: str | None = Header(default=None)) -> JwtDto:
    """Authenticate a developer application given a long-term refresh token or raise a **401** response.
    
    Returns a long-lived access token for the developer application.
    """
    ...

@router.get(
    "/me",
    response_description="General information about the authenticated developer application",
    response_model=DeveloperApplicationDto
)
async def current_developer_application_information(application_id: str = Depends(JWTBearer())) -> DeveloperApplicationDto:
    ...
