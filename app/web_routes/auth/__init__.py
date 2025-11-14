from fastapi import Depends, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse

from ..base import router, templates, AUTH_COOKIE_NAME, COOKIE_MAX_AGE
from ... import schemas
from ...core.deps import get_auth_service
from ...services.auth_service import AuthService


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
    try:
        service.register_user(payload)
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
