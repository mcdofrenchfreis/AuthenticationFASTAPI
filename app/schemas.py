from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, constr


NameStr = constr(strip_whitespace=True, min_length=1, max_length=50, pattern=r"^[A-Za-z ,.'-]+$")
MobileStr = constr(strip_whitespace=True, min_length=8, max_length=15, pattern=r"^\+?\d{8,15}$")


class UserBase(BaseModel):
    email: EmailStr
    first_name: Optional[NameStr] = None
    middle_name: Optional[NameStr] = None
    last_name: Optional[NameStr] = None
    mobile: Optional[MobileStr] = None


class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=128)


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
    code: constr(min_length=6, max_length=6, pattern=r"^\\d{6}$")


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: constr(min_length=6, max_length=6, pattern=r"^\\d{6}$")
    new_password: str = Field(min_length=8, max_length=128)


class MfaSetupRequest(UserLogin):
    """Request body for starting MFA setup using email/password credentials."""


class MfaCodeRequest(BaseModel):
    email: EmailStr
    password: str
    code: constr(min_length=6, max_length=6, pattern=r"^\\d{6}$")


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_url: str


class MfaLoginStartResponse(BaseModel):
    """Response for starting an MFA login flow."""

    mfa_token: str


class MfaLoginVerifyRequest(BaseModel):
    """Request body for completing an MFA login using a one-time MFA token and TOTP code."""

    mfa_token: str
    code: constr(min_length=6, max_length=6, pattern=r"^\\d{6}$")
