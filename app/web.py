from datetime import datetime, timedelta
from typing import Optional
import re
import random

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from . import models, schemas
from .database import get_db
from .utils import verify_password, get_password_hash, create_access_token, decode_token
from .config import ACCESS_TOKEN_EXPIRE_DELTA
from .mailer import send_verification_email

router = APIRouter(tags=["web"]) 

templates = Jinja2Templates(directory="app/templates")

AUTH_COOKIE_NAME = "access_token"
COOKIE_MAX_AGE = int(ACCESS_TOKEN_EXPIRE_DELTA.total_seconds())


def get_current_user_from_cookie(request: Request, db: Session) -> Optional[models.User]:
    token = request.cookies.get(AUTH_COOKIE_NAME)
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    return db.query(models.User).filter(models.User.id == int(user_id)).first()


@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@router.post("/register")
async def register(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    first_name = str(form.get("first_name", "")).strip()
    middle_name = str(form.get("middle_name", "")).strip()
    last_name = str(form.get("last_name", "")).strip()
    mobile = str(form.get("mobile", "")).strip()
    password = str(form.get("password", ""))
    confirm_password = str(form.get("confirm_password", ""))

    existing = db.query(models.User).filter(models.User.email == email).first()
    if existing:
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": "Email already registered",
                "email": email,
                "first_name": first_name,
                "middle_name": middle_name,
                "last_name": last_name,
                "mobile": mobile,
            },
            status_code=400,
        )

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

    user = models.User(
        email=email,
        first_name=first_name,
        middle_name=middle_name,
        last_name=last_name,
        mobile=mobile or None,
        hashed_password=get_password_hash(password),
    )
    db.add(user)
    db.commit()

    # Create verification OTP and email it
    from .models import OtpCode
    code = f"{random.randint(0, 999999):06d}"
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    otp = OtpCode(user_id=user.id, code=code, expires_at=expires_at, purpose="verify")
    db.add(otp)
    db.commit()
    try:
        send_verification_email(user.email, code)
    except Exception:
        pass

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
async def login(request: Request, response: Response, db: Session = Depends(get_db)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    password = str(form.get("password", ""))

    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials", "email": email}, status_code=401)

    if not user.is_verified:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Please verify your account. We sent a code to your email.", "email": email}, status_code=403)

    token = create_access_token({"sub": str(user.id), "email": user.email}, expires_delta=ACCESS_TOKEN_EXPIRE_DELTA)

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
async def forgot(request: Request, db: Session = Depends(get_db)):
    from .models import OtpCode
    from datetime import datetime, timedelta
    import random
    from .mailer import send_otp_email

    form = await request.form()
    email = str(form.get("email", "")).strip()

    user = db.query(models.User).filter(models.User.email == email).first()
    if user:
        code = f"{random.randint(0, 999999):06d}"
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        otp = OtpCode(user_id=user.id, code=code, expires_at=expires_at)
        db.add(otp)
        db.commit()
        try:
            send_otp_email(user.email, code)
        except Exception:
            pass
    # Redirect to OTP verification step regardless of user existence
    return RedirectResponse(url=f"/verify-otp?email={email}&sent=1", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/verify-otp", response_class=HTMLResponse)
async def verify_page(request: Request):
    return templates.TemplateResponse(
        "verify_otp.html",
        {"request": request, "email": request.query_params.get("email", ""), "sent": request.query_params.get("sent")},
    )


@router.post("/verify-otp")
async def verify_otp(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    code = str(form.get("code", "")).strip()

    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return templates.TemplateResponse("verify_otp.html", {"request": request, "error": "Invalid email or code"}, status_code=400)

    from .auth import get_latest_valid_otp

    otp = get_latest_valid_otp(db, user.id, code)
    if not otp:
        return templates.TemplateResponse("verify_otp.html", {"request": request, "error": "Invalid or expired code", "email": email}, status_code=400)

    # Do not consume here; proceed to reset with the code
    return RedirectResponse(url=f"/reset?email={email}&code={code}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/verify-account", response_class=HTMLResponse)
async def verify_account_page(request: Request):
    return templates.TemplateResponse(
        "verify_account.html",
        {"request": request, "email": request.query_params.get("email", "")},
    )


@router.post("/verify-account")
async def post_verify_account(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    code = str(form.get("code", "")).strip()
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return templates.TemplateResponse("verify_account.html", {"request": request, "error": "Invalid email or code", "email": email}, status_code=400)
    from .auth import get_latest_valid_otp
    otp = get_latest_valid_otp(db, user.id, code, purpose="verify")
    if not otp:
        return templates.TemplateResponse("verify_account.html", {"request": request, "error": "Invalid or expired code", "email": email}, status_code=400)
    otp.consumed = True
    user.is_verified = True
    db.commit()
    return RedirectResponse(url="/login?verified=1", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/resend-verification")
async def resend_verification(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    email = str(form.get("email", "")).strip()
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or user.is_verified:
        # Generic message
        return templates.TemplateResponse("verify_account.html", {"request": request, "email": email, "sent": True})
    from .models import OtpCode
    code = f"{random.randint(0, 999999):06d}"
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    otp = OtpCode(user_id=user.id, code=code, expires_at=expires_at, purpose="verify")
    db.add(otp)
    db.commit()
    try:
        send_verification_email(user.email, code)
    except Exception:
        pass
    return templates.TemplateResponse("verify_account.html", {"request": request, "email": email, "sent": True})


@router.get("/reset", response_class=HTMLResponse)
async def reset_page(request: Request):
    return templates.TemplateResponse("reset_password.html", {"request": request, "email": request.query_params.get("email", ""), "code": request.query_params.get("code", "")})


@router.post("/reset")
async def reset_password(request: Request, db: Session = Depends(get_db)):
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

    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return templates.TemplateResponse("reset_password.html", {"request": request, "error": "Invalid email or code", "email": email, "code": code}, status_code=400)

    from .auth import get_latest_valid_otp
    otp = get_latest_valid_otp(db, user.id, code)
    if not otp:
        return templates.TemplateResponse("reset_password.html", {"request": request, "error": "Invalid or expired code", "email": email, "code": code}, status_code=400)

    otp.consumed = True
    user.hashed_password = get_password_hash(new_password)
    db.commit()

    return RedirectResponse(url="/login?reset=1", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user_from_cookie(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})
