from typing import Optional, Dict, List, Tuple
from time import time

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from . import schemas
from .core.deps import get_auth_service
from .services.auth_service import AuthService
from .adapters.auth_adapter import (
    register_user_api,
    login_api,
    verify_otp_api,
    reset_password_api,
    verify_account_api,
    request_password_reset_api,
    resend_verification_api,
    mfa_setup_api,
    mfa_confirm_api,
    mfa_disable_api,
    mfa_login_start_api,
    mfa_login_verify_api,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def get_auth_router() -> APIRouter:
    """Return the JSON auth APIRouter for integration into other FastAPI apps.

    Example:

        from fastapi import FastAPI
        from fastapi_auth_kit.app.auth import get_auth_router

        app = FastAPI()
        app.include_router(get_auth_router())
    """
    return router


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
def register(payload: schemas.UserCreate, background_tasks: BackgroundTasks, service: AuthService = Depends(get_auth_service)):
    user = register_user_api(payload, service, background_tasks)
    return user


@router.post("/login", response_model=schemas.Token)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthService = Depends(get_auth_service),
):
    client_ip = request.client.host if request.client else ""
    # Let adapter handle authentication and domain > HTTPException mapping.
    try:
        token, expires_in = login_api(form_data.username, form_data.password, service)
    except HTTPException as exc:
        # Track failed attempts for 401/403 responses
        if exc.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN):
            _check_and_track_login_attempt(client_ip, form_data.username, success=False)
        raise

    # Successful login clears the attempt history for this IP/email
    _check_and_track_login_attempt(client_ip, form_data.username, success=True)

    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in}


@router.post("/forgot-password")
def forgot_password(payload: schemas.ForgotPasswordRequest, background_tasks: BackgroundTasks, service: AuthService = Depends(get_auth_service)):
    request_password_reset_api(payload.email, service, background_tasks)
    return {"message": "If the email exists, an OTP has been sent."}


@router.post("/verify-otp")
def verify_otp(payload: schemas.VerifyOtpRequest, service: AuthService = Depends(get_auth_service)):
    verify_otp_api(payload.email, payload.code, service, purpose="password_reset")
    return {"message": "OTP verified"}


@router.post("/reset-password")
def reset_password(payload: schemas.ResetPasswordRequest, service: AuthService = Depends(get_auth_service)):
    reset_password_api(payload.email, payload.code, payload.new_password, service)
    return {"message": "Password has been reset"}


@router.post("/verify-account")
def verify_account(payload: schemas.VerifyOtpRequest, service: AuthService = Depends(get_auth_service)):
    verify_account_api(payload.email, payload.code, service)
    return {"message": "Account verified"}


@router.post("/resend-verification")
def resend_verification(payload: schemas.ForgotPasswordRequest, background_tasks: BackgroundTasks, service: AuthService = Depends(get_auth_service)):
    result = resend_verification_api(payload.email, service, background_tasks)
    return result


@router.post("/mfa/setup", response_model=schemas.MfaSetupResponse)
def mfa_setup(payload: schemas.MfaSetupRequest, service: AuthService = Depends(get_auth_service)):
    """Authenticate the user and start TOTP MFA setup.

    This returns a secret and otpauth URL that can be used to configure an authenticator app.
    """
    data = mfa_setup_api(payload.email, payload.password, service)
    return data


@router.post("/mfa/confirm")
def mfa_confirm(payload: schemas.MfaCodeRequest, service: AuthService = Depends(get_auth_service)):
    """Confirm TOTP MFA setup by verifying the provided code."""
    mfa_confirm_api(payload.email, payload.password, payload.code, service)
    return {"message": "MFA has been enabled for this account."}


@router.post("/mfa/disable")
def mfa_disable(payload: schemas.MfaCodeRequest, service: AuthService = Depends(get_auth_service)):
    """Disable TOTP MFA for the authenticated user after verifying a code."""
    mfa_disable_api(payload.email, payload.password, payload.code, service)
    return {"message": "MFA has been disabled for this account."}


@router.post("/login/mfa/start", response_model=schemas.MfaLoginStartResponse)
def login_mfa_start(payload: schemas.UserLogin, service: AuthService = Depends(get_auth_service)):
    """Start an MFA login flow.

    This endpoint is for accounts with MFA enabled. It verifies the user's
    credentials and returns a short-lived MFA token that must be used together
    with a TOTP code at `/auth/login/mfa/verify` to obtain an access token.
    """
    data = mfa_login_start_api(payload.email, payload.password, service)
    return data


@router.post("/login/mfa/verify", response_model=schemas.Token)
def login_mfa_verify(payload: schemas.MfaLoginVerifyRequest, service: AuthService = Depends(get_auth_service)):
    """Complete an MFA login using a one-time MFA token and TOTP code."""
    token, expires_in = mfa_login_verify_api(payload.mfa_token, payload.code, service)
    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in}
