from fastapi import BackgroundTasks, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from ..base import router, templates
from ...core.deps import get_auth_service
from ...services.auth_service import AuthService
from ...adapters.web_auth_adapter import verify_account_web, resend_verification_web


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
    error = verify_account_web(email, code, service)
    if error:
        return templates.TemplateResponse("verify_account.html", {"request": request, "error": error, "email": email}, status_code=400)
    return RedirectResponse(url="/login?verified=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/resend-verification")
async def resend_verification(request: Request, background_tasks: BackgroundTasks, service: AuthService = Depends(get_auth_service)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    resend_verification_web(email, service, background_tasks)
    return templates.TemplateResponse("verify_account.html", {"request": request, "email": email, "sent": True})
