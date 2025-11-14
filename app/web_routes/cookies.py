from typing import Optional
from fastapi import Request
from fastapi.responses import Response

from .base import AUTH_COOKIE_NAME, COOKIE_MAX_AGE
from ..services.auth_service import AuthService
from .. import models
from ..core.settings import settings


def get_token_from_request(request: Request) -> Optional[str]:
    return request.cookies.get(AUTH_COOKIE_NAME)


def get_current_user(request: Request, service: AuthService) -> Optional[models.User]:
    token = get_token_from_request(request)
    if not token:
        return None
    return service.get_user_from_token(token)


def set_login_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        max_age=COOKIE_MAX_AGE,
        samesite=settings.AUTH_COOKIE_SAMESITE,
        secure=settings.AUTH_COOKIE_SECURE,
        path="/",
    )


def clear_login_cookie(response: Response) -> None:
    response.delete_cookie(AUTH_COOKIE_NAME, path="/")
