from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from fastapi.security import HTTPBearer
from jose import JWTError, jwt
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from abandonauth.settings import settings

# Cache of all valid issued tokens. Tokens should be removed after their first use
valid_token_cache = set()


def generate_temp_jwt(user_id: str) -> str:
    """Create a JWT token using the given user ID."""
    expiration = datetime.now(timezone.utc) + timedelta(seconds=settings.JWT_EXPIRES_IN_SECONDS)
    token = jwt.encode(
        claims={
            "user_id": user_id,
            "exp": expiration,
        },
        key=settings.JWT_SECRET.get_secret_value(),
        algorithm=settings.JWT_HASHING_ALGO
    )

    valid_token_cache.add(token)

    return token


class JWTBearer(HTTPBearer):
    """Dependency for routes to enforce JWT auth."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        self.token_data: dict | None = None

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

        if credentials_string not in valid_token_cache:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Token is not valid.")

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

        return self.token_data["user_id"]
