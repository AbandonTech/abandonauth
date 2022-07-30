import os

from fastapi import FastAPI
from prisma import Prisma

from .routes import routers

app = FastAPI(
    title="AbandonAuth",
    version=os.environ.get("VERSION", "local-dev")
)

for router in routers:
    app.include_router(router)

prisma = Prisma(auto_register=True)


@app.on_event("startup")
async def startup() -> None:
    """On startup connect prisma to the database."""
    await prisma.connect()


@app.on_event("shutdown")
async def shutdown() -> None:
    """On shutdown disconnect prisma from the database."""
    if prisma.is_connected():
        await prisma.disconnect()
