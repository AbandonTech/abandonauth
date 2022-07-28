from fastapi import FastAPI

api = FastAPI(
    title="AbandonAuth",
    version="0.0.1"
)


@api.get("/", response_model=dict[str, str])
async def index() -> dict[str, str]:
    """Test endpoint."""
    return {"Hello": "World"}
