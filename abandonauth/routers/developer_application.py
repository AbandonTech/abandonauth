from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from prisma.models import CallbackUri, DeveloperApplication
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_404_NOT_FOUND

from abandonauth.database import prisma_db
from abandonauth.dependencies.auth.hash import (
    generate_refresh_token,
    get_hashed_data,
    verify_data,
)
from abandonauth.dependencies.auth.jwt import DeveloperAppJwtBearer, JWTBearer, generate_long_lived_jwt
from abandonauth.models import (
    CreateCallbackUriDto,
    CreateDeveloperApplicationDto,
    DeveloperApplicationDto,
    DeveloperApplicationWithCallbackUriDto,
    JwtDto,
    LoginDeveloperApplicationDto,
)
from abandonauth.models.auth import JwtClaimsDataDto
from abandonauth.settings import settings

router = APIRouter(
    prefix="/developer_application",
    tags=["Developer Applications"],
)


@router.post(
    "",
    summary="Create a new developer application and retrieve a refresh token. This token will never be visible again.",
    response_description="The refresh token for the new developer account.",
    response_model=CreateDeveloperApplicationDto,
)
async def create_developer_application(
        token_data: JwtClaimsDataDto = Depends(JWTBearer()),
) -> CreateDeveloperApplicationDto:
    """
    Create a new developer application owned by the currently authenticated User.

    Returns the permanent refresh token for the account. This token can only be manually changed.
    """
    refresh_token = generate_refresh_token()
    hashed_token = get_hashed_data(refresh_token)

    dev_app = await DeveloperApplication.prisma().create({
        "owner_id": token_data.user_id,
        "refresh_token": hashed_token,
    })

    return CreateDeveloperApplicationDto(id=dev_app.id, owner_id=dev_app.owner_id, token=refresh_token)


@router.post(
    "/login",
    summary="Exchange a developer application refresh token for a short-lived AbandonAuth JWT",
    response_description="A short-lived JWT to authenticate a developer application",
    response_model=JwtDto,
)
async def login_developer_application(login_data: LoginDeveloperApplicationDto) -> JwtDto:
    """
    Authenticate a developer application given a long-term refresh token or raise a **401** response.

    Returns a short-lived exchange token for the developer application.
    """
    dev_app = await DeveloperApplication.prisma().find_unique(
        {
            "id": str(login_data.id),
        },
    )

    if not dev_app or not verify_data(login_data.refresh_token, dev_app.refresh_token):
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid username or refresh token",
        )

    return JwtDto(token=generate_long_lived_jwt(dev_app.id, settings.ABANDON_AUTH_DEVELOPER_APP_ID))


@router.delete(
    "/{application_id}",
    summary="Delete the developer application with the given id",
    response_description="The deleted application data",
    response_model=DeveloperApplicationDto,
)
async def delete_developer_application(
        application_id: UUID,
        token_data: JwtClaimsDataDto = Depends(JWTBearer()),
) -> DeveloperApplicationDto:
    """Delete the given developer application if the current user owns the application."""
    dev_app = await DeveloperApplication.prisma().find_unique({
        "id": str(application_id),
    })

    if dev_app and token_data.user_id == dev_app.owner_id:
        deleted = await DeveloperApplication.prisma().delete({
            "id": dev_app.id,
        })

        # It should not be possible for this condition to fail. Adding for Pyright
        if deleted:
            return DeveloperApplicationDto(id=deleted.id, owner_id=deleted.owner_id)

    raise HTTPException(status_code=HTTP_404_NOT_FOUND)


@router.patch(
    "/{application_id}/reset_token",
    summary="Change the refresh token on a developer application. This is not reversible.",
    response_description="The newly generated refresh token for the application.",
    response_model=CreateDeveloperApplicationDto,
)
async def change_application_refresh_token(
        application_id: UUID,
        token_data: JwtClaimsDataDto = Depends(JWTBearer()),
) -> CreateDeveloperApplicationDto:
    """
    Generate and set a new refresh token for the given developer application.

    This action is not reversible and destroys the existing refresh token for the application.
    """
    dev_app = await DeveloperApplication.prisma().find_unique({
        "id": str(application_id),
    })

    if dev_app and token_data.user_id == dev_app.owner_id:
        refresh_token = generate_refresh_token()
        hashed_token = get_hashed_data(refresh_token)

        updated = await DeveloperApplication.prisma().update(
            where={
                "id": dev_app.id,
            },
            data={
                "refresh_token": hashed_token,
            },
        )

        # It should not be possible for this condition to fail. Adding for Pyright
        if updated:
            return CreateDeveloperApplicationDto(id=updated.id, owner_id=updated.owner_id, token=refresh_token)

    raise HTTPException(status_code=HTTP_404_NOT_FOUND)


@router.get(
    "/me",
    summary="Verify and retrieve information for a developer application",
    response_description="General information about the authenticated developer application",
    response_model=DeveloperApplicationDto,
)
async def current_developer_application_information(
        token_data: JwtClaimsDataDto = Depends(DeveloperAppJwtBearer()),
) -> DeveloperApplicationDto:
    """
    Get information about the developer application from a jwt.

    This function must be defined before other endpoints that use path params at the same path
    """
    dev_app = await DeveloperApplication.prisma().find_unique({
        "id": token_data.user_id,
    })

    if dev_app is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    return DeveloperApplicationDto(id=dev_app.id, owner_id=dev_app.owner_id)


@router.get(
    "/{application_id}",
    summary="Retrieve the given application if it belongs to the currently authenticated user",
    response_description="General information about the developer application",
    response_model=DeveloperApplicationWithCallbackUriDto,
)
async def get_developer_application(
    application_id: UUID,
    token_data: JwtClaimsDataDto = Depends(JWTBearer()),
) -> DeveloperApplicationWithCallbackUriDto:
    """Get information about the given developer application if the requesting user owns the developer app."""
    dev_app = await DeveloperApplication.prisma().find_unique(
        where={"id": str(application_id)},
        include={"callback_uris": True},
    )

    if not (dev_app and token_data.user_id == dev_app.owner_id):
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    callbacks = [x.uri for x in dev_app.callback_uris] if dev_app.callback_uris else []

    return DeveloperApplicationWithCallbackUriDto(
        id=dev_app.id,
        owner_id=dev_app.owner_id,
        callback_uris=callbacks,
    )


@router.patch(
    "/{application_id}/callback_uris",
    summary="Update the callback URIs for the given developer application",
    response_description="The new list of callback URIs for the developer application",
    response_model=DeveloperApplicationDto,
)
async def update_developer_application_callback_uris(
        application_id: UUID,
        callback_uris: list[str],
        token_data: JwtClaimsDataDto = Depends(JWTBearer()),
) -> DeveloperApplicationDto:
    """
    Replace the valid callback URIs for the given developer application and return the given developer application.

    Create all callback URIs that do not exist yet.
    Delete all callback URIs that already exist and were not given in this request.
    Callback URIs that already exist and were given in this request will remain in the database unaltered.
    """
    dev_app = await DeveloperApplication.prisma().find_unique(
        where={"id": str(application_id)},
        include={"callback_uris": True},
    )

    if not (dev_app and token_data.user_id == dev_app.owner_id):
        raise HTTPException(status_code=HTTP_404_NOT_FOUND)

    if dev_app.callback_uris:
        existing_callback_uris: dict[str, CallbackUri] = {x.uri: x for x in dev_app.callback_uris}
    else:
        existing_callback_uris = {}

    # Gather URIs that do not exist yet and stage them for creation
    callback_uris_to_create: list[CreateCallbackUriDto] = []

    for uri in callback_uris:
        if uri not in existing_callback_uris:
            to_create = CreateCallbackUriDto(developer_application_id=dev_app.id, uri=uri)
            callback_uris_to_create.append(to_create)

    # Gather URIs that already exist and were not specified in the request and stage them for deletion
    uris_to_delete = [
        existing_callback_uris[delete_uri]
        for delete_uri in existing_callback_uris
        if delete_uri not in callback_uris
    ]

    # Batch the creation of new URIs and the deletion of URIs that were not given in the request
    # Only URIs that were passed into the request should exist after the entire exchange is done
    async with prisma_db.batch_() as batcher:
        for create_uri in callback_uris_to_create:
            batcher.callbackuri.create(dict(create_uri))  # pyright: ignore [reportArgumentType]

        for delete_uri in uris_to_delete:
            batcher.callbackuri.delete(where={"id": delete_uri.id})

    return DeveloperApplicationDto(id=dev_app.id, owner_id=dev_app.owner_id)
