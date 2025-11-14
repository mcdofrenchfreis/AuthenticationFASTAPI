from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ResendVerificationStatus(str, Enum):
    SENT = "sent"
    USER_NOT_FOUND = "user_not_found"
    ALREADY_VERIFIED = "already_verified"


@dataclass
class ResendVerificationResult:
    status: ResendVerificationStatus
    code: Optional[str] = None
