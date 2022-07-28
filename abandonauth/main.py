from fastapi import FastAPI
from fastapi.responses import RedirectResponse


api = FastAPI(
    title="AbandonAuth",
    version="0.0.1"
)


@api.get("/")
async def index():
    return RedirectResponse("/docs")
