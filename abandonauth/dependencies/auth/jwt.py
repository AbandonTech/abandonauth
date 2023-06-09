from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from fastapi.security import HTTPBearer
from jose import JWTError, jwt
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN
from typing import Any

from abandonauth.settings import settings

# Cache of all valid issued tokens. Tokens should be removed after their first use
valid_token_cache = set()


def generate_refresh_token() -> str:
    ...


def _generate_jwt(user_id: str, long_lived: bool = False) -> str:
    """Generate an AbandonAuth long-lived or short-lived JWT for the given user.

    Creates a JWT containing the user ID and expiration of the token.
    long-lived = True should be used for user login sessions (i.e. website user or internal application login).
    long-lived = False should be used for any token exchange (i.e. Discord OAuth login).
    """
    if long_lived:
        exp_seconds = settings.JWT_EXPIRES_IN_SECONDS_LONG_LIVED
    else:
        exp_seconds = settings.JWT_EXPIRES_IN_SECONDS_SHORT_LIVED

    expiration = datetime.now(timezone.utc) + timedelta(seconds=exp_seconds)

    token = jwt.encode(
        claims={
            "user_id": user_id,
            "exp": expiration,
            "lifespan": "long" if long_lived else "short"
        },
        key=settings.JWT_SECRET.get_secret_value(),
        algorithm=settings.JWT_HASHING_ALGO
    )
    if not long_lived:
        valid_token_cache.add(token)

    return token


def generate_long_lived_jwt(user_id: str) -> str:
    return _generate_jwt(user_id, long_lived=True)


def generate_short_lived_jwt(user_id: str) -> str:
    """Create a JWT token using the given user ID."""
    return _generate_jwt(user_id, long_lived=False)


class JWTBearer(HTTPBearer):
    """Dependency for routes to enforce JWT auth."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

        self.token_data: dict[str, Any] | None = None

    async def __call__(self, request: Request) -> str:
        """
        Retrieve user from a jwt token provided in headers.

        If no token is present, a 403 will be raised
        If the token is invalid, a 403 will be raised
        If the token has expired, a 400 will be raised
        """
        credentials = await super().__call__(request)
        if credentials is None:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid authentication credentials",
            )

        credentials_string = credentials.credentials

        try:
            self.token_data = jwt.decode(credentials_string, settings.JWT_SECRET.get_secret_value())
        except JWTError:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid token format"
            )

        if self.token_data["exp"] < datetime.utcnow().timestamp():
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST,
                detail="Token has expired"
            )

        # If token is short-lived/exchange token check if it currently exists in the token cache
        # This means short-lived tokens will only work with a single worker
        # This is a hack and a future version will resolve this https://github.com/AbandonTech/abandonauth/issues/12
        if self.token_data["lifespan"] == "short" and credentials_string not in valid_token_cache:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Token is not valid.")

        return self.token_data["user_id"]
