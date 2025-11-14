from importlib import resources as importlib_resources

from fastapi import APIRouter
from fastapi.templating import Jinja2Templates

from ..core.settings import settings

router = APIRouter(tags=["web"])  # Shared tag for all web routes

_templates_dir = importlib_resources.files("app").joinpath("templates")
templates = Jinja2Templates(directory=str(_templates_dir))

AUTH_COOKIE_NAME = "access_token"
COOKIE_MAX_AGE = int(settings.access_token_expire_delta.total_seconds())
