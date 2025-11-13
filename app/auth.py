from datetime import datetime, timedelta
import random
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from . import schemas, models
from .database import get_db
from .utils import get_password_hash, verify_password, create_access_token, validate_password_policy
from .config import ACCESS_TOKEN_EXPIRE_DELTA, OTP_EXP_MINUTES
from .mailer import send_otp_email, send_verification_email

router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def authenticate_user(db: Session, email: str, password: str) -> Optional[models.User]:
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


@router.post("/register", response_model=schemas.UserOut)
def register(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    pw_err = validate_password_policy(payload.password)
    if pw_err:
        raise HTTPException(status_code=400, detail=pw_err)
    user = models.User(
        email=payload.email,
        first_name=payload.first_name,
        middle_name=payload.middle_name,
        last_name=payload.last_name,
        mobile=payload.mobile,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create verification OTP and email it
    code = f"{random.randint(0, 999999):06d}"
    expires_at = datetime.utcnow() + timedelta(minutes=OTP_EXP_MINUTES)
    otp = models.OtpCode(user_id=user.id, code=code, expires_at=expires_at, purpose="verify")
    db.add(otp)
    db.commit()
    try:
        send_verification_email(user.email, code)
    except Exception:
        pass
    return user


@router.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account not verified")
    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        expires_delta=ACCESS_TOKEN_EXPIRE_DELTA,
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": int(ACCESS_TOKEN_EXPIRE_DELTA.total_seconds()),
    }


@router.post("/forgot-password")
def forgot_password(payload: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        # Do not reveal whether email exists
        return {"message": "If the email exists, an OTP has been sent."}

    code = f"{random.randint(0, 999999):06d}"
    expires_at = datetime.utcnow() + timedelta(minutes=OTP_EXP_MINUTES)

    otp = models.OtpCode(user_id=user.id, code=code, expires_at=expires_at)
    db.add(otp)
    db.commit()

    try:
        send_otp_email(user.email, code)
    except Exception:
        # Do not leak errors; still respond generically
        pass

    return {"message": "If the email exists, an OTP has been sent."}


def get_latest_valid_otp(db: Session, user_id: int, code: str, purpose: Optional[str] = None):
    otp = (
        db.query(models.OtpCode)
        .filter(
            models.OtpCode.user_id == user_id,
            models.OtpCode.code == code,
            models.OtpCode.consumed == False,  # noqa: E712
            models.OtpCode.expires_at > datetime.utcnow(),
            *( [models.OtpCode.purpose == purpose] if purpose else [] ),
        )
        .order_by(models.OtpCode.created_at.desc())
        .first()
    )
    return otp


@router.post("/verify-otp")
def verify_otp(payload: schemas.VerifyOtpRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or code")

    otp = get_latest_valid_otp(db, user.id, payload.code, purpose="password_reset")
    if not otp:
        raise HTTPException(status_code=400, detail="Invalid or expired code")

    # Mark as consumed so it cannot be reused
    otp.consumed = True
    db.commit()

    return {"message": "OTP verified"}


@router.post("/reset-password")
def reset_password(payload: schemas.ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or code")

    otp = get_latest_valid_otp(db, user.id, payload.code)
    if not otp:
        raise HTTPException(status_code=400, detail="Invalid or expired code")

    # Consume OTP and update password
    otp.consumed = True
    user.hashed_password = get_password_hash(payload.new_password)
    db.commit()

    return {"message": "Password has been reset"}


@router.post("/verify-account")
def verify_account(payload: schemas.VerifyOtpRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or code")
    otp = get_latest_valid_otp(db, user.id, payload.code, purpose="verify")
    if not otp:
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    otp.consumed = True
    user.is_verified = True
    db.commit()
    return {"message": "Account verified"}


@router.post("/resend-verification")
def resend_verification(payload: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        return {"message": "If the email exists, a verification code has been sent."}
    if user.is_verified:
        return {"message": "Account already verified"}
    code = f"{random.randint(0, 999999):06d}"
    expires_at = datetime.utcnow() + timedelta(minutes=OTP_EXP_MINUTES)
    otp = models.OtpCode(user_id=user.id, code=code, expires_at=expires_at, purpose="verify")
    db.add(otp)
    db.commit()
    try:
        send_verification_email(user.email, code)
    except Exception:
        pass
    return {"message": "If the email exists, a verification code has been sent."}
