from .discord import router as discord_router
from .github import router as github_router
from .google import router as google_router
from .index import router as index_router

routers = [
    discord_router,
    github_router,
    google_router,
    index_router,
]