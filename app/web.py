from datetime import datetime, timedelta
from typing import Optional
import re
import random
from importlib import resources as importlib_resources

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import models, schemas
from .utils import decode_token
from .core.settings import settings
from .core.deps import get_auth_service
from .services.auth_service import AuthService

router = APIRouter(tags=["web"]) 

_templates_dir = importlib_resources.files("app").joinpath("templates")
templates = Jinja2Templates(directory=str(_templates_dir))

AUTH_COOKIE_NAME = "access_token"
COOKIE_MAX_AGE = int(settings.access_token_expire_delta.total_seconds())


def get_current_user_from_cookie(request: Request, service: AuthService) -> Optional[models.User]:
    token = request.cookies.get(AUTH_COOKIE_NAME)
    if not token:
        return None
    return service.get_user_from_token(token)


@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@router.post("/register")
async def register(request: Request, service: AuthService = Depends(get_auth_service)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    first_name = str(form.get("first_name", "")).strip()
    middle_name = str(form.get("middle_name", "")).strip()
    last_name = str(form.get("last_name", "")).strip()
    mobile = str(form.get("mobile", "")).strip()
    password = str(form.get("password", ""))
    confirm_password = str(form.get("confirm_password", ""))

    # Existence and validation handled in service

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

    # Use service to register and send verification
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
    try:
        user = service.register_user(payload)
    except ValueError as e:
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

    user = service.authenticate(email, password)
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials", "email": email}, status_code=401)

    if not user.is_verified:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Please verify your account. We sent a code to your email.", "email": email}, status_code=403)

    token, _expires = service.create_login_token(user)

    resp = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        max_age=COOKIE_MAX_AGE,
        samesite="lax",
        secure=False,
        path="/",
    )
    return resp


@router.get("/logout")
async def logout():
    resp = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(AUTH_COOKIE_NAME, path="/")
    return resp


@router.get("/forgot", response_class=HTMLResponse)
async def forgot_page(request: Request):
    return templates.TemplateResponse("forgot.html", {"request": request})


@router.post("/forgot")
async def forgot(request: Request, service: AuthService = Depends(get_auth_service)):

    form = await request.form()
    email = str(form.get("email", "")).strip()

    service.request_password_reset(email)
    # Redirect to OTP verification step regardless of user existence
    return RedirectResponse(url=f"/verify-otp?email={email}&sent=1", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/verify-otp", response_class=HTMLResponse)
async def verify_page(request: Request):
    return templates.TemplateResponse(
        "verify_otp.html",
        {"request": request, "email": request.query_params.get("email", ""), "sent": request.query_params.get("sent")},
    )


@router.post("/verify-otp")
async def verify_otp(request: Request, service: AuthService = Depends(get_auth_service)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    code = str(form.get("code", "")).strip()

    ok = service.verify_otp(email, code, purpose="password_reset")
    if not ok:
        return templates.TemplateResponse("verify_otp.html", {"request": request, "error": "Invalid or expired code", "email": email}, status_code=400)
    return RedirectResponse(url=f"/reset?email={email}&code={code}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/verify-account", response_class=HTMLResponse)
async def verify_account_page(request: Request):
    return templates.TemplateResponse(
        "verify_account.html",
        {"request": request, "email": request.query_params.get("email", "")},
    )


@router.post("/verify-account")
async def post_verify_account(request: Request, service: AuthService = Depends(get_auth_service)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    code = str(form.get("code", "")).strip()
    ok = service.verify_account(email, code)
    if not ok:
        return templates.TemplateResponse("verify_account.html", {"request": request, "error": "Invalid or expired code", "email": email}, status_code=400)
    return RedirectResponse(url="/login?verified=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/resend-verification")
async def resend_verification(request: Request, service: AuthService = Depends(get_auth_service)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    status_msg = service.resend_verification(email)
    if status_msg == "already":
        return templates.TemplateResponse("verify_account.html", {"request": request, "email": email, "sent": True})
    return templates.TemplateResponse("verify_account.html", {"request": request, "email": email, "sent": True})


@router.get("/reset", response_class=HTMLResponse)
async def reset_page(request: Request):
    return templates.TemplateResponse("reset_password.html", {"request": request, "email": request.query_params.get("email", ""), "code": request.query_params.get("code", "")})


@router.post("/reset")
async def reset_password(request: Request, service: AuthService = Depends(get_auth_service)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    code = str(form.get("code", "")).strip()
    new_password = str(form.get("new_password", ""))
    confirm_password = str(form.get("confirm_password", ""))

    # Validate password rules (same as registration)
    def pw_invalid(msg: str):
        return templates.TemplateResponse(
            "reset_password.html",
            {"request": request, "error": msg, "email": email, "code": code},
            status_code=400,
        )

    if new_password != confirm_password:
        return pw_invalid("Passwords do not match")
    if len(new_password) < 8:
        return pw_invalid("Password must be at least 8 characters")
    if not re.search(r"[a-z]", new_password):
        return pw_invalid("Password must include a lowercase letter")
    if not re.search(r"[A-Z]", new_password):
        return pw_invalid("Password must include an uppercase letter")
    if not re.search(r"\d", new_password):
        return pw_invalid("Password must include a number")
    if not re.search(r"[^A-Za-z0-9]", new_password):
        return pw_invalid("Password must include a special character")
    if re.search(r"\s", new_password):
        return pw_invalid("Password must not contain spaces")

    ok = service.reset_password(email, code, new_password)
    if not ok:
        return templates.TemplateResponse("reset_password.html", {"request": request, "error": "Invalid email or code", "email": email, "code": code}, status_code=400)

    return RedirectResponse(url="/login?reset=1", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, service: AuthService = Depends(get_auth_service)):
    user = get_current_user_from_cookie(request, service)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})
