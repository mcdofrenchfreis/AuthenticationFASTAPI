from fastapi import BackgroundTasks, HTTPException, status

from .. import schemas
from ..services.auth_service import AuthService
from ..domain.errors import (
    UserAlreadyExistsError,
    PasswordPolicyError,
    InvalidCredentialsError,
    OtpInvalidOrExpiredError,
)
from ..domain.results import ResendVerificationResult, ResendVerificationStatus
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


def login_api(username: str, password: str, service: AuthService) -> tuple[str, int]:
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
    result: ResendVerificationResult = service.resend_verification(email)

    if result.status is ResendVerificationStatus.ALREADY_VERIFIED:
        return {"message": "Account already verified"}

    if result.status is ResendVerificationStatus.SENT and result.code:
        background_tasks.add_task(send_verification_email, email, result.code)

    # For USER_NOT_FOUND and SENT, behave as though an email was sent without revealing user existence.
    return {"message": "If the email exists, a verification code has been sent."}


def mfa_setup_api(email: str, password: str, service: AuthService) -> dict:
    """Authenticate user and begin TOTP MFA setup.

    Returns the secret and otpauth_url to be used for QR code / authenticator apps.
    """
    try:
        user = service.authenticate(email, password)
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    secret, otpauth_url = service.begin_mfa_setup(user)
    return {"secret": secret, "otpauth_url": otpauth_url}


def mfa_confirm_api(email: str, password: str, code: str, service: AuthService) -> None:
    """Authenticate user and confirm MFA setup with the provided TOTP code."""
    try:
        user = service.authenticate(email, password)
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    try:
        service.confirm_mfa_setup(user, code)
    except OtpInvalidOrExpiredError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


def mfa_disable_api(email: str, password: str, code: str, service: AuthService) -> None:
    """Authenticate user and disable MFA after verifying a TOTP code."""
    try:
        user = service.authenticate(email, password)
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    try:
        service.disable_mfa(user, code)
    except OtpInvalidOrExpiredError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


def mfa_login_start_api(email: str, password: str, service: AuthService) -> dict:
    """Start an MFA login: verify password and return a short-lived MFA token.

    This does not return an access token. The client must call the MFA verify
    endpoint with the MFA token and a TOTP code to complete login.
    """
    try:
        user = service.authenticate(email, password)
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account not verified")

    if not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled for this account")

    mfa_token = service.create_mfa_token(user)
    return {"mfa_token": mfa_token}


def mfa_login_verify_api(mfa_token: str, code: str, service: AuthService) -> tuple[str, int]:
    """Complete an MFA login by verifying a TOTP code and issuing an access token."""
    user = service.get_user_from_mfa_token(mfa_token)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired MFA token")

    try:
        service.verify_mfa_code(user, code)
    except OtpInvalidOrExpiredError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    token, expires_in = service.create_login_token(user)
    return token, expires_in
