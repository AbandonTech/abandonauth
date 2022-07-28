from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from abandonauth.constants import version

api = FastAPI(
    title="AbandonAuth",
    version=version
)


@api.get("/")
async def index():
    return RedirectResponse("/docs")
