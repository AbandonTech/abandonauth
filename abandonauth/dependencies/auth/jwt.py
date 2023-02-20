from datetime import datetime, timedelta, timezone

from classy_config import ConfigValue
from fastapi import HTTPException, Request
from fastapi.security import HTTPBearer
from jose import JWTError, jwt


def generate_jwt(
    user_id: int,
    *,
    expires_in: int = ConfigValue("JWT_EXPIRES_IN", int),
    secret: str = ConfigValue("JWT_SECRET", str),
    hash_algorithm: str = ConfigValue("JWT_HASHING_ALGO", str),
) -> str:
    """Create a JWT token using the given user ID."""
    expiration = datetime.now(timezone.utc) + timedelta(expires_in)
    token = jwt.encode(
        claims={
            "user_id": user_id,
            "exp": expiration,
        },
        key=secret,
        algorithm=hash_algorithm
    )
    return token


class JWTBearer(HTTPBearer):
    """Dependency for routes to enforce JWT auth."""

    def __init__(
        self,
        secret: str = ConfigValue("JWT_SECRET", str),
        **kwargs
    ) -> None:
        super().__init__(**kwargs)

        self._secret = secret
        self.token_data: dict | None = None

    async def __call__(self, request: Request) -> int:
        """
        Retrieve user from a jwt token provided in headers.

        If no token is present, a 403 will be raised
        If the token is invalid, a 403 will be raised
        If the token has expired, a 400 will be raised
        """
        credentials = await super().__call__(request)
        credentials_string = credentials.credentials

        try:
            self.token_data = jwt.decode(credentials_string, self._secret)
        except JWTError:
            raise HTTPException(status_code=403, detail="Invalid token format")

        if self.token_data["exp"] < datetime.utcnow().timestamp():
            raise HTTPException(status_code=400, detail="Token has expired")

        return self.token_data["user_id"]
