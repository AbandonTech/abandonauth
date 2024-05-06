from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.security import HTTPBearer
from jose import JWTError, jwt
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from abandonauth.models.auth import JwtClaimsDataDto, LifespanEnum, ScopeEnum
from abandonauth.settings import settings

# Cache of all valid issued tokens. Tokens should be removed after their first use
valid_token_cache = set()

IGNORE_AUD_DECODE_OPTIONS = {"verify_aud": False}


def _generate_jwt(user_id: str, application_id_aud: str, *, long_lived: bool = False) -> str:
    """
    Generate an AbandonAuth long-lived or short-lived JWT for the given user.

    Creates a JWT containing the user ID and expiration of the token.
    application_id_aud is the verified developer application ID that will be consuming the token
    long-lived = True should be used for user login sessions (i.e. website user or internal application login).
    long-lived = False should be used for any token exchange (i.e. Discord OAuth login).
    """
    if long_lived:
        exp_seconds = settings.JWT_EXPIRES_IN_SECONDS_LONG_LIVED
    else:
        exp_seconds = settings.JWT_EXPIRES_IN_SECONDS_SHORT_LIVED

    expiration = datetime.now(timezone.utc) + timedelta(seconds=exp_seconds)

    if long_lived and application_id_aud == settings.ABANDON_AUTH_DEVELOPER_APP_ID:
        scope = f"{ScopeEnum.abandonauth} {ScopeEnum.identify}"
    else:
        scope = ScopeEnum.identify

    claims = JwtClaimsDataDto(
        user_id=user_id,
        exp=expiration,
        scope=scope,
        aud=application_id_aud,
        lifespan=LifespanEnum.long if long_lived else LifespanEnum.short,
    )

    token = jwt.encode(
        claims=dict(claims),
        key=settings.JWT_SECRET.get_secret_value(),
        algorithm=settings.JWT_HASHING_ALGO,
    )
    if not long_lived:
        valid_token_cache.add(token)

    return token


def decode_jwt(
        token: str,
        aud: str | None = None,
        required_scope: ScopeEnum = ScopeEnum.abandonauth,
) -> JwtClaimsDataDto:
    """
    Decode and return all claim data for the given JWT.

    Raises errors if invalid, or unauthorized JWT is supplied.
    """
    try:
        decode_kwargs = {"audience": aud} if aud else {"options": IGNORE_AUD_DECODE_OPTIONS}

        token_data = jwt.decode(
            token,
            settings.JWT_SECRET.get_secret_value(),
            **decode_kwargs,  # pyright: ignore [reportArgumentType]
        )
    except JWTError as e:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Invalid token format",
        ) from e

    if token_data["exp"] < datetime.now(timezone.utc).timestamp():
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Token has expired",
        )

    if required_scope != ScopeEnum.none and required_scope not in token_data["scope"]:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="JWT lacks the required scope to access this endpoint.",
        )

    # If token is short-lived/exchange token check if it currently exists in the token cache
    # This means short-lived tokens will only work with a single worker
    # This is a hack and a future version will resolve this https://github.com/AbandonTech/abandonauth/issues/12
    if token_data["lifespan"] == "short" and token not in valid_token_cache:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Token is not valid.")

    return JwtClaimsDataDto(**dict(token_data))


def generate_long_lived_jwt(user_id: str, application_id_aud: str) -> str:
    """Generate a long lived JWT token using the given user ID."""
    return _generate_jwt(user_id, application_id_aud, long_lived=True)


def generate_short_lived_jwt(user_id: str, application_id_aud: str) -> str:
    """Create a JWT token using the given user ID."""
    return _generate_jwt(user_id, application_id_aud, long_lived=False)


class JWTBearer(HTTPBearer):
    """Dependency for routes to enforce JWT auth."""

    def __init__(
            self,
            scope: ScopeEnum = ScopeEnum.abandonauth,
            aud: str | None = None,
            **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)

        self.token_data: dict[str, Any]
        self.aud = aud
        self.required_scope = scope

    async def __call__(self, request: Request) -> JwtClaimsDataDto:  # pyright: ignore [reportIncompatibleMethodOverride]
        """
        Retrieve user from a jwt token provided in headers.

        If no token is present, a 403 will be raised
        If the token is invalid, a 403 will be raised
        If the token has expired, a 403 will be raised
        """
        credentials = await super().__call__(request)

        if credentials is None:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid authentication credentials",
            )

        credentials_string = credentials.credentials

        return decode_jwt(credentials_string, self.aud, self.required_scope)


class DeveloperAppJwtBearer(JWTBearer):
    """JWTBearer class for authorizing developer application tokens."""

    def __init__(
            self,
            **kwargs: Any,
    ) -> None:
        super().__init__(
            scope=ScopeEnum.abandonauth,
            aud=settings.ABANDON_AUTH_DEVELOPER_APP_ID,
            **kwargs,
        )


class OptionalDeveloperAppJwtBearer(HTTPBearer):
    """
    Dependency for routes to utilize JWT auth when the JWT is optional.

    This dependency should usually be paired with an additional auth method where an exception should be raised if
    no authentication method is provided.
    """

    def __init__(
            self,
            **kwargs: Any,
    ) -> None:
        super().__init__(
            auto_error=False,
            **kwargs,
        )

        self.token_data: dict[str, Any]
        self.aud = settings.ABANDON_AUTH_DEVELOPER_APP_ID
        self.required_scope = ScopeEnum.abandonauth

    async def __call__(self, request: Request) -> JwtClaimsDataDto | None:  # pyright: ignore [reportIncompatibleMethodOverride]
        """
        Retrieve user from a jwt token provided in headers if the token was provided.

        If no token is present, returns None
        If the token is invalid, a 403 will be raised
        If the token has expired, a 403 will be raised
        """
        credentials = await super().__call__(request)

        if credentials is None:
            return None

        credentials_string = credentials.credentials

        return decode_jwt(credentials_string, self.aud, self.required_scope)
