from __future__ import annotations
from typing import Optional, Protocol
from datetime import datetime

from .. import models


class UserRepositoryProtocol(Protocol):
    def get_by_email(self, email: str) -> Optional[models.User]:
        ...

    def get_by_id(self, user_id: int) -> Optional[models.User]:
        ...

    def create_user(
        self,
        *,
        email: str,
        first_name: Optional[str],
        middle_name: Optional[str],
        last_name: Optional[str],
        mobile: Optional[str],
        hashed_password: str,
    ) -> models.User:
        ...

    def set_password(self, user: models.User, hashed_password: str) -> None:
        ...

    def mark_verified(self, user: models.User) -> None:
        ...


class OtpRepositoryProtocol(Protocol):
    def create_otp(self, *, user_id: int, code: str, expires_at: datetime, purpose: str = "password_reset") -> models.OtpCode:
        ...

    def latest_valid(self, *, user_id: int, code: str, purpose: Optional[str] = None) -> Optional[models.OtpCode]:
        ...

    def consume(self, otp: models.OtpCode) -> None:
        ...
