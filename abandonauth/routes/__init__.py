from .discord import router as register_router
from .index import router as index_router

routers = [
    index_router,
    register_router,
]
