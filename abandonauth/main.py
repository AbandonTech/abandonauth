import os

from fastapi import FastAPI

api = FastAPI(
    title="AbandonAuth",
    version=os.environ.get("VERSION", "local-dev")
)


@api.get("/", response_model=dict[str, str])
async def index() -> dict[str, str]:
    """Test endpoint."""
    return {"Hello": "World"}
