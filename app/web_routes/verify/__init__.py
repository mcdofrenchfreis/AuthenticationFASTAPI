from fastapi import Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from ..base import router, templates
from ...core.deps import get_auth_service
from ...services.auth_service import AuthService


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
