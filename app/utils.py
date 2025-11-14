from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from jose import JWTError, jwt
from passlib.context import CryptContext

from .core.settings import settings

pwd_context = CryptContext(schemes=["bcrypt_sha256", "bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + (expires_delta or timedelta(minutes=60))

    # Standard registered claims
    to_encode.setdefault("iat", now)
    to_encode.setdefault("jti", str(uuid4()))
    to_encode["exp"] = expire

    # Optional issuer metadata
    if settings.AUTH_ISSUER:
        to_encode.setdefault("iss", settings.AUTH_ISSUER)

    encoded_jwt = jwt.encode(to_encode, settings.AUTH_SECRET_KEY, algorithm=settings.AUTH_ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.AUTH_SECRET_KEY, algorithms=[settings.AUTH_ALGORITHM])
        return payload
    except JWTError:
        return None


def validate_password_policy(password: str) -> Optional[str]:
    """Return None if password passes policy, else an error message."""
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    if any(ch.isspace() for ch in password):
        return "Password must not contain spaces"
    if not any(ch.islower() for ch in password):
        return "Password must include at least one lowercase letter"
    if not any(ch.isupper() for ch in password):
        return "Password must include at least one uppercase letter"
    if not any(ch.isdigit() for ch in password):
        return "Password must include at least one number"
    if not any(not ch.isalnum() for ch in password):
        return "Password must include at least one special character"
    return None
