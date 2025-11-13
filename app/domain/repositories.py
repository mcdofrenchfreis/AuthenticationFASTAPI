from __future__ import annotations
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session

from .. import models


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_email(self, email: str) -> Optional[models.User]:
        return self.db.query(models.User).filter(models.User.email == email).first()

    def get_by_id(self, user_id: int) -> Optional[models.User]:
        return self.db.query(models.User).filter(models.User.id == user_id).first()

    def create_user(self, *, email: str, first_name: Optional[str], middle_name: Optional[str], last_name: Optional[str], mobile: Optional[str], hashed_password: str) -> models.User:
        user = models.User(
            email=email,
            first_name=first_name,
            middle_name=middle_name,
            last_name=last_name,
            mobile=mobile,
            hashed_password=hashed_password,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def set_password(self, user: models.User, hashed_password: str) -> None:
        user.hashed_password = hashed_password
        self.db.commit()

    def mark_verified(self, user: models.User) -> None:
        user.is_verified = True
        self.db.commit()


class OtpRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_otp(self, *, user_id: int, code: str, expires_at: datetime, purpose: str = "password_reset") -> models.OtpCode:
        otp = models.OtpCode(user_id=user_id, code=code, expires_at=expires_at, purpose=purpose)
        self.db.add(otp)
        self.db.commit()
        return otp

    def latest_valid(self, *, user_id: int, code: str, purpose: Optional[str] = None) -> Optional[models.OtpCode]:
        q = (
            self.db.query(models.OtpCode)
            .filter(
                models.OtpCode.user_id == user_id,
                models.OtpCode.code == code,
                models.OtpCode.consumed == False,  # noqa: E712
                models.OtpCode.expires_at > datetime.utcnow(),
            )
            .order_by(models.OtpCode.created_at.desc())
        )
        if purpose:
            q = q.filter(models.OtpCode.purpose == purpose)
        return q.first()

    def consume(self, otp: models.OtpCode) -> None:
        otp.consumed = True
        self.db.commit()
