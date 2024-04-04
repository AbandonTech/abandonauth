from typing import Annotated

from fastapi import HTTPException, Depends
from prisma.models import DeveloperApplication
from starlette.status import HTTP_403_FORBIDDEN

from abandonauth.dependencies.auth.refresh_token import verify_refresh_token
from abandonauth.models.developer_application import LoginDeveloperApplicationDto


async def authenticate_developer_app_from_optional_app_id_and_secret(
        login_data: LoginDeveloperApplicationDto | None = None
) -> DeveloperApplication | None:
    """Attempt to fetch login data from request body and authenticate the developer application with provided creds.

    Returns None if no credentials were provided.
    Raises an exception if credentials were provided and are not valid.
    """
    if login_data is None:
        return None

    dev_app = await DeveloperApplication.prisma().find_unique(
        {
            "id": login_data.id
        }
    )

    if not dev_app or not verify_refresh_token(login_data.refresh_token, dev_app.refresh_token):
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Invalid username or refresh token",
        )

    return dev_app


LoginDevAppWithOptionalCredentialsDep = Annotated[
    DeveloperApplication | None,
    Depends(authenticate_developer_app_from_optional_app_id_and_secret)
]
