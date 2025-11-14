from fastapi import BackgroundTasks, HTTPException, status

from .. import schemas
from ..services.auth_service import AuthService
from ..domain.errors import (
    UserAlreadyExistsError,
    PasswordPolicyError,
    InvalidCredentialsError,
    OtpInvalidOrExpiredError,
    AccountAlreadyVerifiedError,
)
from ..infrastructure.mailer import send_otp_email, send_verification_email


def register_user_api(payload: schemas.UserCreate, service: AuthService, background_tasks: BackgroundTasks) -> schemas.UserOut:
    try:
        user, code = service.register_user(payload)
    except UserAlreadyExistsError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PasswordPolicyError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Send verification email asynchronously
    background_tasks.add_task(send_verification_email, user.email, code)
    return user


def login_api(username: str, password: str, service: AuthService) -> tuple[schemas.Token, int, int]:
    from ..utils import create_access_token  # avoid circular import at module load

    try:
        user = service.authenticate(username, password)
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account not verified")

    token, expires_in = service.create_login_token(user)
    return token, expires_in


def verify_otp_api(email: str, code: str, service: AuthService, purpose: str | None = None) -> None:
    try:
        service.verify_otp(email, code, purpose=purpose)
    except OtpInvalidOrExpiredError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


def reset_password_api(email: str, code: str, new_password: str, service: AuthService) -> None:
    try:
        service.reset_password(email, code, new_password)
    except OtpInvalidOrExpiredError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


def verify_account_api(email: str, code: str, service: AuthService) -> None:
    try:
        service.verify_account(email, code)
    except OtpInvalidOrExpiredError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


def request_password_reset_api(email: str, service: AuthService, background_tasks: BackgroundTasks) -> None:
    code = service.request_password_reset(email)
    if code:
        background_tasks.add_task(send_otp_email, email, code)


def resend_verification_api(email: str, service: AuthService, background_tasks: BackgroundTasks) -> dict:
    try:
        code = service.resend_verification(email)
    except AccountAlreadyVerifiedError:
        return {"message": "Account already verified"}

    if code:
        background_tasks.add_task(send_verification_email, email, code)

    return {"message": "If the email exists, a verification code has been sent."}
