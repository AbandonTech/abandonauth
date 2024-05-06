import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from abandonauth.database import prisma_db
from abandonauth.routers import routers


app = FastAPI(
    title="AbandonAuth",
    version=os.environ.get("VERSION", "local-dev"),
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
