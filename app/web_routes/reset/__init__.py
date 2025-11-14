import re
from fastapi import Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from ..base import router, templates
from ...core.deps import get_auth_service
from ...services.auth_service import AuthService


@router.get("/forgot", response_class=HTMLResponse)
async def forgot_page(request: Request):
    return templates.TemplateResponse("forgot.html", {"request": request})


@router.post("/forgot")
async def forgot(request: Request, service: AuthService = Depends(get_auth_service)):
    form = await request.form()
    email = str(form.get("email", "")).strip()

    service.request_password_reset(email)
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
