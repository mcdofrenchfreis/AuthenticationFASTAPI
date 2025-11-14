from __future__ import annotations
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from datetime import timedelta
from typing import Optional


class Settings(BaseSettings):
    # Security
    AUTH_SECRET_KEY: str = Field(default="change-this-secret", env="AUTH_SECRET_KEY")
    AUTH_ALGORITHM: str = Field(default="HS256", env="AUTH_ALGORITHM")
    AUTH_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60, env="AUTH_ACCESS_TOKEN_EXPIRE_MINUTES")
    AUTH_OTP_EXP_MINUTES: int = Field(default=10, env="AUTH_OTP_EXP_MINUTES")

    # Database
    DATABASE_URL: str = Field(default="postgresql+psycopg2://user:password@localhost:5432/auth_db", env="DATABASE_URL")

    # SMTP
    SMTP_HOST: str = Field(default="smtp.gmail.com", env="SMTP_HOST")
    SMTP_PORT: int = Field(default=587, env="SMTP_PORT")
    SMTP_USER: str = Field(default="", env="SMTP_USER")
    SMTP_PASSWORD: str = Field(default="", env="SMTP_PASSWORD")
    SMTP_FROM: Optional[str] = Field(default=None, env="SMTP_FROM")
    SMTP_FROM_NAME: str = Field(default="Auth App", env="SMTP_FROM_NAME")

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @property
    def access_token_expire_delta(self) -> timedelta:
        return timedelta(minutes=int(self.AUTH_ACCESS_TOKEN_EXPIRE_MINUTES))

    @property
    def otp_expire_delta(self) -> timedelta:
        return timedelta(minutes=int(self.AUTH_OTP_EXP_MINUTES))


settings = Settings()
