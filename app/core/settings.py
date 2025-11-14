from __future__ import annotations
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from datetime import timedelta
from typing import Optional


class Settings(BaseSettings):
    # Environment
    ENV: str = Field(default="dev", env="ENV")

    # Security
    AUTH_SECRET_KEY: str = Field(default="change-this-secret", env="AUTH_SECRET_KEY")
    AUTH_ALGORITHM: str = Field(default="HS256", env="AUTH_ALGORITHM")
    AUTH_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60, env="AUTH_ACCESS_TOKEN_EXPIRE_MINUTES")
    AUTH_OTP_EXP_MINUTES: int = Field(default=10, env="AUTH_OTP_EXP_MINUTES")

    # Optional JWT metadata
    AUTH_ISSUER: Optional[str] = Field(default=None, env="AUTH_ISSUER")

    # Cookie settings for web auth
    AUTH_COOKIE_SECURE: bool = Field(default=False, env="AUTH_COOKIE_SECURE")
    AUTH_COOKIE_SAMESITE: str = Field(default="lax", env="AUTH_COOKIE_SAMESITE")

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

    @property
    def is_dev(self) -> bool:
        return self.ENV.lower() == "dev"

    @property
    def is_stage(self) -> bool:
        return self.ENV.lower() == "stage"

    @property
    def is_prod(self) -> bool:
        return self.ENV.lower() == "prod"

    def validate_for_runtime(self) -> None:
        """Perform basic security checks based on the current environment.

        In non-dev environments this will raise if critical security settings are unsafe
        (e.g. default secret key, insecure cookies).
        """
        # Only enforce strict checks outside of dev
        if self.is_dev:
            return

        # Secret key must not be the default and should be reasonably strong
        if not self.AUTH_SECRET_KEY or self.AUTH_SECRET_KEY == "change-this-secret" or len(self.AUTH_SECRET_KEY) < 32:
            raise RuntimeError(
                "AUTH_SECRET_KEY is not set to a strong value. "
                "Set a long, random secret in your environment for non-dev deployments."
            )

        # Require secure cookies by default outside dev
        if not self.AUTH_COOKIE_SECURE:
            raise RuntimeError(
                "AUTH_COOKIE_SECURE must be True in non-dev environments to prevent auth cookies "
                "from being sent over insecure HTTP."
            )


settings = Settings()
