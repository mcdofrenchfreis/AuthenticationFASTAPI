from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
import random
from typing import Optional, Tuple

from ..domain.repositories import UserRepository, OtpRepository
from ..core.settings import Settings
from .. import models, schemas
from ..utils import (
    get_password_hash,
    verify_password,
    create_access_token,
    validate_password_policy,
    decode_token,
)
from ..mailer import send_otp_email, send_verification_email


@dataclass
class AuthService:
    user_repo: UserRepository
    otp_repo: OtpRepository
    settings: Settings

    # Users
    def register_user(self, payload: schemas.UserCreate) -> models.User:
        existing = self.user_repo.get_by_email(payload.email)
        if existing:
            raise ValueError("Email already registered")
        pw_err = validate_password_policy(payload.password)
        if pw_err:
            raise ValueError(pw_err)
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
        try:
            send_verification_email(user.email, code)
        except Exception:
            pass
        return user

    def authenticate(self, email: str, password: str) -> Optional[models.User]:
        user = self.user_repo.get_by_email(email)
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
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
    def request_password_reset(self, email: str) -> None:
        user = self.user_repo.get_by_email(email)
        if not user:
            return None
        code = f"{random.randint(0, 999999):06d}"
        expires_at = datetime.utcnow() + self.settings.otp_expire_delta
        self.otp_repo.create_otp(user_id=user.id, code=code, expires_at=expires_at, purpose="password_reset")
        try:
            send_otp_email(user.email, code)
        except Exception:
            pass
        return None

    def verify_otp(self, email: str, code: str, purpose: Optional[str] = None) -> bool:
        user = self.user_repo.get_by_email(email)
        if not user:
            return False
        otp = self.otp_repo.latest_valid(user_id=user.id, code=code, purpose=purpose)
        if not otp:
            return False
        # Do not consume here; only validate existence. Consumption happens at the action step (e.g., reset_password).
        return True

    def reset_password(self, email: str, code: str, new_password: str) -> bool:
        user = self.user_repo.get_by_email(email)
        if not user:
            return False
        # Ensure the OTP is specifically for password reset and is still valid
        otp = self.otp_repo.latest_valid(user_id=user.id, code=code, purpose="password_reset")
        if not otp:
            return False
        self.otp_repo.consume(otp)
        self.user_repo.set_password(user, get_password_hash(new_password))
        return True

    def verify_account(self, email: str, code: str) -> bool:
        user = self.user_repo.get_by_email(email)
        if not user:
            return False
        otp = self.otp_repo.latest_valid(user_id=user.id, code=code, purpose="verify")
        if not otp:
            return False
        self.otp_repo.consume(otp)
        self.user_repo.mark_verified(user)
        return True

    def resend_verification(self, email: str) -> str:
        user = self.user_repo.get_by_email(email)
        if not user:
            return "sent"
        if user.is_verified:
            return "already"
        code = f"{random.randint(0, 999999):06d}"
        expires_at = datetime.utcnow() + self.settings.otp_expire_delta
        self.otp_repo.create_otp(user_id=user.id, code=code, expires_at=expires_at, purpose="verify")
        try:
            send_verification_email(user.email, code)
        except Exception:
            pass
        return "sent"
