from fastapi import Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from ..base import router, templates
from ..cookies import get_current_user
from ...core.deps import get_auth_service
from ...services.auth_service import AuthService
from ...domain.errors import OtpInvalidOrExpiredError


@router.get("/settings/mfa", response_class=HTMLResponse)
async def mfa_settings(request: Request, service: AuthService = Depends(get_auth_service)):
    user = get_current_user(request, service)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    # Initial settings page; secret/otpauth_url only shown after starting setup
    return templates.TemplateResponse(
        "mfa_settings.html",
        {
            "request": request,
            "user": user,
            "secret": None,
            "otpauth_url": None,
            "error": None,
            "message": request.query_params.get("message"),
        },
    )


@router.post("/settings/mfa/start")
async def mfa_settings_start(request: Request, service: AuthService = Depends(get_auth_service)):
    user = get_current_user(request, service)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    secret, otpauth_url = service.begin_mfa_setup(user)
    return templates.TemplateResponse(
        "mfa_settings.html",
        {
            "request": request,
            "user": user,
            "secret": secret,
            "otpauth_url": otpauth_url,
            "error": None,
            "message": None,
        },
    )


@router.post("/settings/mfa/confirm")
async def mfa_settings_confirm(request: Request, service: AuthService = Depends(get_auth_service)):
    user = get_current_user(request, service)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    form = await request.form()
    code = str(form.get("code", "")).strip()
    try:
        service.confirm_mfa_setup(user, code)
    except OtpInvalidOrExpiredError as e:
        # Re-show settings with error; do not show secret/otpauth again by default
        return templates.TemplateResponse(
            "mfa_settings.html",
            {
                "request": request,
                "user": user,
                "secret": None,
                "otpauth_url": None,
                "error": str(e),
                "message": None,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(url="/settings/mfa?message=mfa_enabled", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/settings/mfa/disable")
async def mfa_settings_disable(request: Request, service: AuthService = Depends(get_auth_service)):
    user = get_current_user(request, service)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    form = await request.form()
    code = str(form.get("code", "")).strip()
    try:
        service.disable_mfa(user, code)
    except OtpInvalidOrExpiredError as e:
        return templates.TemplateResponse(
            "mfa_settings.html",
            {
                "request": request,
                "user": user,
                "secret": None,
                "otpauth_url": None,
                "error": str(e),
                "message": None,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(url="/settings/mfa?message=mfa_disabled", status_code=status.HTTP_303_SEE_OTHER)
