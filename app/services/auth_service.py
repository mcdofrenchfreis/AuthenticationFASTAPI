from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
import random
from typing import Optional, Tuple

from ..domain.interfaces import UserRepositoryProtocol, OtpRepositoryProtocol
from ..domain.errors import (
    UserAlreadyExistsError,
    PasswordPolicyError,
    InvalidCredentialsError,
    OtpInvalidOrExpiredError,
    AccountAlreadyVerifiedError,
)
from ..core.settings import Settings
from .. import models, schemas
from ..utils import (
    get_password_hash,
    verify_password,
    create_access_token,
    validate_password_policy,
    decode_token,
)


@dataclass
class AuthService:
    user_repo: UserRepositoryProtocol
    otp_repo: OtpRepositoryProtocol
    settings: Settings

    # Users
    def register_user(self, payload: schemas.UserCreate) -> Tuple[models.User, str]:
        existing = self.user_repo.get_by_email(payload.email)
        if existing:
            raise UserAlreadyExistsError("Email already registered")
        pw_err = validate_password_policy(payload.password)
        if pw_err:
            raise PasswordPolicyError(pw_err)
        user = self.user_repo.create_user(
            email=payload.email,
            first_name=payload.first_name,
            middle_name=payload.middle_name,
            last_name=payload.last_name,
            mobile=payload.mobile,
            hashed_password=get_password_hash(payload.password),
        )
        # verification code
        code = f"{random.randint(0, 999999):06d}"
        expires_at = datetime.utcnow() + self.settings.otp_expire_delta
        self.otp_repo.create_otp(user_id=user.id, code=code, expires_at=expires_at, purpose="verify")
        return user, code

    def authenticate(self, email: str, password: str) -> models.User:
        user = self.user_repo.get_by_email(email)
        if not user:
            raise InvalidCredentialsError("Invalid credentials")
        if not verify_password(password, user.hashed_password):
            raise InvalidCredentialsError("Invalid credentials")
        return user

    def create_login_token(self, user: models.User) -> Tuple[str, int]:
        token = create_access_token(
            data={"sub": str(user.id), "email": user.email},
            expires_delta=self.settings.access_token_expire_delta,
        )
        return token, int(self.settings.access_token_expire_delta.total_seconds())

    def get_user_from_token(self, token: str) -> Optional[models.User]:
        payload = decode_token(token)
        if not payload:
            return None
        sub = payload.get("sub")
        if not sub:
            return None
        try:
            user_id = int(sub)
        except (TypeError, ValueError):
            return None
        return self.user_repo.get_by_id(user_id)

    # OTP flows
    def request_password_reset(self, email: str) -> Optional[str]:
        """Create a password reset OTP if the user exists and return the code.

        Returns None if the user does not exist so callers can behave as if an
        email was sent without revealing user existence.
        """
        user = self.user_repo.get_by_email(email)
        if not user:
            return None
        code = f"{random.randint(0, 999999):06d}"
        expires_at = datetime.utcnow() + self.settings.otp_expire_delta
        self.otp_repo.create_otp(user_id=user.id, code=code, expires_at=expires_at, purpose="password_reset")
        return code

    def verify_otp(self, email: str, code: str, purpose: Optional[str] = None) -> None:
        user = self.user_repo.get_by_email(email)
        if not user:
            raise OtpInvalidOrExpiredError("Invalid email or code")
        otp = self.otp_repo.latest_valid(user_id=user.id, code=code, purpose=purpose)
        if not otp:
            raise OtpInvalidOrExpiredError("Invalid or expired code")
        # Do not consume here; only validate existence. Consumption happens at the action step (e.g., reset_password).
        return None

    def reset_password(self, email: str, code: str, new_password: str) -> None:
        user = self.user_repo.get_by_email(email)
        if not user:
            raise OtpInvalidOrExpiredError("Invalid email or code")
        # Ensure the OTP is specifically for password reset and is still valid
        otp = self.otp_repo.latest_valid(user_id=user.id, code=code, purpose="password_reset")
        if not otp:
            raise OtpInvalidOrExpiredError("Invalid or expired code")
        self.otp_repo.consume(otp)
        self.user_repo.set_password(user, get_password_hash(new_password))
        return None

    def verify_account(self, email: str, code: str) -> None:
        user = self.user_repo.get_by_email(email)
        if not user:
            raise OtpInvalidOrExpiredError("Invalid email or code")
        otp = self.otp_repo.latest_valid(user_id=user.id, code=code, purpose="verify")
        if not otp:
            raise OtpInvalidOrExpiredError("Invalid or expired code")
        self.otp_repo.consume(otp)
        self.user_repo.mark_verified(user)
        return None

    def resend_verification(self, email: str) -> Optional[str]:
        """Create a new verification OTP for the user and return the code.

        Returns None if the user does not exist. Raises AccountAlreadyVerifiedError
        if the account is already verified.
        """
        user = self.user_repo.get_by_email(email)
        if not user:
            # For security, behave as though we sent an email even if the user does not exist.
            return None
        if user.is_verified:
            raise AccountAlreadyVerifiedError("Account already verified")
        code = f"{random.randint(0, 999999):06d}"
        expires_at = datetime.utcnow() + self.settings.otp_expire_delta
        self.otp_repo.create_otp(user_id=user.id, code=code, expires_at=expires_at, purpose="verify")
        return code
