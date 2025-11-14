from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    email: EmailStr
    first_name: Optional[str] = None
    middle_name: Optional[str] = None
    last_name: Optional[str] = None
    mobile: Optional[str] = None


class UserCreate(UserBase):
    password: str = Field(min_length=6)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(UserBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class VerifyOtpRequest(BaseModel):
    email: EmailStr
    code: str


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str = Field(min_length=6)


class MfaSetupRequest(UserLogin):
    """Request body for starting MFA setup using email/password credentials."""


class MfaCodeRequest(BaseModel):
    email: EmailStr
    password: str
    code: str


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_url: str


class MfaLoginStartResponse(BaseModel):
    """Response for starting an MFA login flow."""

    mfa_token: str


class MfaLoginVerifyRequest(BaseModel):
    """Request body for completing an MFA login using a one-time MFA token and TOTP code."""

    mfa_token: str
    code: str
