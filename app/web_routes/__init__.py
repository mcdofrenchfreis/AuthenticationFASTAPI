from .base import router
# Import grouped subpackages to register routes via side effects
from . import pages  # noqa: F401
from . import auth  # noqa: F401
from . import reset  # noqa: F401
from . import verify  # noqa: F401
from . import dashboard  # noqa: F401
from . import mfa  # noqa: F401

__all__ = ["router"]
