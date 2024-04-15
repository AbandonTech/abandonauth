from .developer_application import router as developer_router
from .discord import router as discord_router
from .github import router as github_router
from .google import router as google_router
from .index import router as index_router
from .ui import router as ui_router
from .test_router import router as test_router

from settings import settings

routers = [
    developer_router,
    discord_router,
    github_router,
    google_router,
    index_router,
    ui_router
]

if settings.DEBUG:
    routers.append(test_router)
