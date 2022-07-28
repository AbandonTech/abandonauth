from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

# TODO: ENV VAR
JWT_SECRET = "123"


class JWTBearer(HTTPBearer):
    """Dependency for routes to enforce JWT auth."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.token_data: dict | None = None

    async def __call__(self, request: Request):
        """Check if the supplied credentials are valid for this endpoint."""
        credentials: HTTPAuthorizationCredentials = await super().__call__(
            request)
        credentials_string = credentials.credentials

        try:
            self.token_data = jwt.decode(credentials_string, JWT_SECRET)
        except JWTError:
            raise HTTPException(status_code=403, detail="JWT is invalid")
