from .main import create_app, app
from .auth import router as auth_router
from .web import router as web_router
from .services.auth_service import AuthService
from .core.settings import settings, Settings

__all__ = [
    "create_app",
    "app",
    "auth_router",
    "web_router",
    "AuthService",
    "settings",
    "Settings",
]
