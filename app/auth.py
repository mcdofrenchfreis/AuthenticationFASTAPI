from typing import Optional, Dict, List, Tuple
from time import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from . import schemas, models
from .core.deps import get_auth_service
from .services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


# Simple in-memory rate limiting for login attempts.
# This is process-local and intended as a lightweight safeguard for small deployments.
_LOGIN_ATTEMPTS: Dict[Tuple[str, str], List[float]] = {}
_LOGIN_WINDOW_SECONDS = 60.0
_LOGIN_MAX_ATTEMPTS = 5


def _check_and_track_login_attempt(ip: str, email: str, success: bool) -> None:
    """Track login attempts and enforce a simple rate limit.

    - Keyed by (ip, email)
    - Counts attempts within the last _LOGIN_WINDOW_SECONDS seconds
    - If failures exceed _LOGIN_MAX_ATTEMPTS, raise HTTP 429
    - Successful logins clear the attempt history for that key
    """
    if not ip:
        ip = "unknown"

    key = (ip, email.lower())
    now = time()

    attempts = _LOGIN_ATTEMPTS.get(key, [])
    # Drop attempts outside the window
    attempts = [ts for ts in attempts if now - ts <= _LOGIN_WINDOW_SECONDS]

    if success:
        # Clear attempts on success to avoid locking out legitimate users
        if key in _LOGIN_ATTEMPTS:
            del _LOGIN_ATTEMPTS[key]
        return

    # Failure path: enforce limit
    if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
        )

    # Record this failed attempt
    attempts.append(now)
    _LOGIN_ATTEMPTS[key] = attempts


@router.post("/register", response_model=schemas.UserOut)
def register(payload: schemas.UserCreate, service: AuthService = Depends(get_auth_service)):
    try:
        user = service.register_user(payload)
        return user
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login", response_model=schemas.Token)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthService = Depends(get_auth_service),
):
    client_ip = request.client.host if request.client else ""

    user = service.authenticate(form_data.username, form_data.password)
    if not user:
        _check_and_track_login_attempt(client_ip, form_data.username, success=False)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_verified:
        # Treat unverified login attempts as failures for rate limiting
        _check_and_track_login_attempt(client_ip, form_data.username, success=False)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account not verified")

    # Successful login clears the attempt history for this IP/email
    _check_and_track_login_attempt(client_ip, form_data.username, success=True)

    token, expires_in = service.create_login_token(user)
    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in}


@router.post("/forgot-password")
def forgot_password(payload: schemas.ForgotPasswordRequest, service: AuthService = Depends(get_auth_service)):
    service.request_password_reset(payload.email)
    return {"message": "If the email exists, an OTP has been sent."}


@router.post("/verify-otp")
def verify_otp(payload: schemas.VerifyOtpRequest, service: AuthService = Depends(get_auth_service)):
    ok = service.verify_otp(payload.email, payload.code, purpose="password_reset")
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    return {"message": "OTP verified"}


@router.post("/reset-password")
def reset_password(payload: schemas.ResetPasswordRequest, service: AuthService = Depends(get_auth_service)):
    ok = service.reset_password(payload.email, payload.code, payload.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid email or code")
    return {"message": "Password has been reset"}


@router.post("/verify-account")
def verify_account(payload: schemas.VerifyOtpRequest, service: AuthService = Depends(get_auth_service)):
    ok = service.verify_account(payload.email, payload.code)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    return {"message": "Account verified"}


@router.post("/resend-verification")
def resend_verification(payload: schemas.ForgotPasswordRequest, service: AuthService = Depends(get_auth_service)):
    status_msg = service.resend_verification(payload.email)
    if status_msg == "already":
        return {"message": "Account already verified"}
    return {"message": "If the email exists, a verification code has been sent."}
