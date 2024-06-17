import tomllib
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from abandonauth.database import prisma_db
from abandonauth.routers import routers
from abandonauth.settings import settings

with Path("../pyproject.toml").open("rb") as f:
    pyproject = tomllib.load(f)

app = FastAPI(
    title="AbandonAuth",
    version=pyproject["tool"]["poetry"]["version"],
)

allowed_origins = [settings.ABANDON_AUTH_SITE_URL]

if settings.DEBUG:
    allowed_origins.append("*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="./abandonauth/static"), name="static")

for router in routers:
    app.include_router(router)


@app.on_event("startup")
async def startup() -> None:
    """On startup connect prisma to the database."""
    await prisma_db.connect()


@app.on_event("shutdown")
async def shutdown() -> None:
    """On shutdown disconnect prisma from the database."""
    if prisma_db.is_connected():
        await prisma_db.disconnect()
