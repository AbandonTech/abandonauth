import classy_config

classy_config.register_config(".env")

from fastapi import FastAPI

from .routes import routers

app = FastAPI(
    title="AbandonAuth",
    version="0.0.1"
)

for router in routers:
    app.include_router(router)
