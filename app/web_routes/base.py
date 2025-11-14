from datetime import datetime
from typing import Optional
from importlib import resources as importlib_resources

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates

from .. import models, schemas
from ..core.settings import settings
from ..core.deps import get_auth_service
from ..services.auth_service import AuthService

router = APIRouter(tags=["web"])  # Shared tag for all web routes

_templates_dir = importlib_resources.files("app").joinpath("templates")
templates = Jinja2Templates(directory=str(_templates_dir))

AUTH_COOKIE_NAME = "access_token"
COOKIE_MAX_AGE = int(settings.access_token_expire_delta.total_seconds())


def get_current_user_from_cookie(request: Request, service: AuthService) -> Optional[models.User]:
    token = request.cookies.get(AUTH_COOKIE_NAME)
    if not token:
        return None
    return service.get_user_from_token(token)
