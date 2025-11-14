from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from . import schemas, models
from .core.deps import get_auth_service
from .services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=schemas.UserOut)
def register(payload: schemas.UserCreate, service: AuthService = Depends(get_auth_service)):
    try:
        user = service.register_user(payload)
        return user
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), service: AuthService = Depends(get_auth_service)):
    user = service.authenticate(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account not verified")
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
