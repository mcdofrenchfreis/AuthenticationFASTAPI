from __future__ import annotations
from typing import Generator
from fastapi import Depends
from sqlalchemy.orm import Session

from .settings import settings, Settings
from ..database import get_db
from ..domain.repositories import UserRepository, OtpRepository
from ..services.auth_service import AuthService


def get_settings() -> Settings:
    return settings


def get_user_repo(db: Session = Depends(get_db)) -> UserRepository:
    return UserRepository(db)


def get_otp_repo(db: Session = Depends(get_db)) -> OtpRepository:
    return OtpRepository(db)


def get_auth_service(
    user_repo: UserRepository = Depends(get_user_repo),
    otp_repo: OtpRepository = Depends(get_otp_repo),
    cfg: Settings = Depends(get_settings),
) -> AuthService:
    return AuthService(user_repo=user_repo, otp_repo=otp_repo, settings=cfg)
