from fastapi import BackgroundTasks, Depends, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse

from ..base import router, templates
from ..cookies import set_login_cookie, clear_login_cookie
from ... import schemas
from ...core.deps import get_auth_service
from ...services.auth_service import AuthService
from ...adapters.web_auth_adapter import register_web, login_web


@router.post("/register")
async def register(request: Request, background_tasks: BackgroundTasks, service: AuthService = Depends(get_auth_service)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    first_name = str(form.get("first_name", "")).strip()
    middle_name = str(form.get("middle_name", "")).strip()
    last_name = str(form.get("last_name", "")).strip()
    mobile = str(form.get("mobile", "")).strip()
    password = str(form.get("password", ""))
    confirm_password = str(form.get("confirm_password", ""))

    if password != confirm_password:
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": "Passwords do not match",
                "email": email,
                "first_name": first_name,
                "middle_name": middle_name,
                "last_name": last_name,
                "mobile": mobile,
            },
            status_code=400,
        )

    try:
        payload = schemas.UserCreate(
            email=email,
            first_name=first_name or None,
            middle_name=middle_name or None,
            last_name=last_name or None,
            mobile=mobile or None,
            password=password,
        )
    except Exception as e:
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": str(e),
                "email": email,
                "first_name": first_name,
                "middle_name": middle_name,
                "last_name": last_name,
                "mobile": mobile,
            },
            status_code=400,
        )
    error = register_web(payload, service, background_tasks)
    if error:
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": error,
                "email": email,
                "first_name": first_name,
                "middle_name": middle_name,
                "last_name": last_name,
                "mobile": mobile,
            },
            status_code=400,
        )

    return RedirectResponse(url=f"/verify-account?email={email}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "registered": request.query_params.get("registered"),
            "reset": request.query_params.get("reset"),
            "verified": request.query_params.get("verified"),
        },
    )


@router.post("/login")
async def login(request: Request, response: Response, service: AuthService = Depends(get_auth_service)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    password = str(form.get("password", ""))

    user, error = login_web(email, password, service)
    if error or not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": error or "Invalid credentials", "email": email}, status_code=401)

    if not user.is_verified:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Please verify your account. We sent a code to your email.", "email": email}, status_code=403)

    # If MFA is enabled for this user, redirect to second-step verification
    if user.mfa_enabled:
        mfa_token = service.create_mfa_token(user)
        return RedirectResponse(url=f"/login/mfa?token={mfa_token}", status_code=status.HTTP_303_SEE_OTHER)

    token, _expires = service.create_login_token(user)

    resp = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    set_login_cookie(resp, token)
    return resp


@router.get("/logout")
async def logout():
    resp = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    clear_login_cookie(resp)
    return resp


@router.get("/login/mfa", response_class=HTMLResponse)
async def login_mfa_page(request: Request, token: str | None = None):
    if not token:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("login_mfa.html", {"request": request, "mfa_token": token, "error": None})


@router.post("/login/mfa")
async def login_mfa(request: Request, response: Response, service: AuthService = Depends(get_auth_service)):
    form = await request.form()
    mfa_token = str(form.get("mfa_token", ""))
    code = str(form.get("code", "")).strip()

    user = service.get_user_from_mfa_token(mfa_token)
    if not user:
        return templates.TemplateResponse(
            "login_mfa.html",
            {"request": request, "mfa_token": mfa_token, "error": "Invalid or expired MFA token"},
            status_code=400,
        )

    try:
        service.verify_mfa_code(user, code)
    except Exception:
        return templates.TemplateResponse(
            "login_mfa.html",
            {"request": request, "mfa_token": mfa_token, "error": "Invalid or expired code"},
            status_code=400,
        )

    token, _expires = service.create_login_token(user)
    resp = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    set_login_cookie(resp, token)
    return resp
