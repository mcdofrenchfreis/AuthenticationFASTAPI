from fastapi import Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..base import router, templates
from ..cookies import get_current_user
from ...core.deps import get_auth_service
from ...services.auth_service import AuthService


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, service: AuthService = Depends(get_auth_service)):
    user = get_current_user(request, service)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})
