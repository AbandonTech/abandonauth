from abandonauth.routers.developer_application import router as developer_router
from abandonauth.routers.discord import router as discord_router
from abandonauth.routers.github import router as github_router
from abandonauth.routers.google import router as google_router
from abandonauth.routers.index import router as index_router
from abandonauth.routers.password_login import router as password_login_router
from abandonauth.routers.ui import router as ui_router
from abandonauth.settings import settings

routers = [
    developer_router,
    discord_router,
    github_router,
    google_router,
    index_router,
    ui_router,
]

if settings.DEBUG:
    routers.append(password_login_router)
