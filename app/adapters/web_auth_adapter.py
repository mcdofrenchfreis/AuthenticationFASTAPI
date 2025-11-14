from __future__ import annotations

from typing import Optional

from fastapi import BackgroundTasks

from .. import schemas, models
from ..services.auth_service import AuthService
from ..domain.errors import (
    UserAlreadyExistsError,
    PasswordPolicyError,
    InvalidCredentialsError,
    OtpInvalidOrExpiredError,
    AccountAlreadyVerifiedError,
)
from ..infrastructure.mailer import send_otp_email, send_verification_email


def register_web(payload: schemas.UserCreate, service: AuthService, background_tasks: BackgroundTasks) -> Optional[str]:
    try:
        user, code = service.register_user(payload)
    except (UserAlreadyExistsError, PasswordPolicyError) as e:
        return str(e)

    background_tasks.add_task(send_verification_email, payload.email, code)
    return None


def login_web(email: str, password: str, service: AuthService) -> tuple[Optional[models.User], Optional[str]]:
    try:
        user = service.authenticate(email, password)
        return user, None
    except InvalidCredentialsError:
        return None, "Invalid credentials"


def verify_otp_web(email: str, code: str, purpose: Optional[str], service: AuthService) -> Optional[str]:
    try:
        service.verify_otp(email, code, purpose=purpose)
        return None
    except OtpInvalidOrExpiredError:
        return "Invalid or expired code"


def reset_password_web(email: str, code: str, new_password: str, service: AuthService) -> Optional[str]:
    try:
        service.reset_password(email, code, new_password)
        return None
    except OtpInvalidOrExpiredError:
        return "Invalid email or code"


def verify_account_web(email: str, code: str, service: AuthService) -> Optional[str]:
    try:
        service.verify_account(email, code)
        return None
    except OtpInvalidOrExpiredError:
        return "Invalid or expired code"


def request_password_reset_web(email: str, service: AuthService, background_tasks: BackgroundTasks) -> None:
    code = service.request_password_reset(email)
    if code:
        background_tasks.add_task(send_otp_email, email, code)


def resend_verification_web(email: str, service: AuthService, background_tasks: BackgroundTasks) -> None:
    try:
        code = service.resend_verification(email)
    except AccountAlreadyVerifiedError:
        return None

    if code:
        background_tasks.add_task(send_verification_email, email, code)

    return None
