from __future__ import annotations


class UserAlreadyExistsError(Exception):
    """Raised when attempting to register an email that is already in use."""


class PasswordPolicyError(Exception):
    """Raised when a password does not satisfy the configured password policy."""


class InvalidCredentialsError(Exception):
    """Raised when login credentials are invalid."""


class OtpInvalidOrExpiredError(Exception):
    """Raised when an OTP is invalid, expired, or does not match the intended purpose."""
