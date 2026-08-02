"""
Optional authentication support (SOP v4.0 Phase 1).

Anonymous scanning is and remains the default. Authentication is opt-in and is
driven entirely through the ``AuthenticationManager`` + the four providers
(cookies / bearer / JWT / custom headers) and the ``SessionValidator``.

This package is a thin provider layer over the existing engine module
``core.auth_manager`` (which owns the ``AuthSession`` model, detection and
login helpers) and re-exports its public API for convenience.
"""

from core.auth.authentication_manager import (
    PROVIDERS,
    AuthenticationManager,
)
from core.auth.base import AuthSpec, BaseProvider
from core.auth.cookie_provider import CookieProvider
from core.auth.bearer_provider import BearerProvider
from core.auth.jwt_provider import JwtProvider
from core.auth.header_provider import HeaderProvider
from core.auth.session_validator import (
    SessionValidationResult,
    SessionValidator,
)

# Re-export the engine's auth model so consumers only import core.auth.
from core.auth_manager import (  # noqa: E402  (intentional facade)
    AUTH_METHOD_LABELS,
    AUTH_STATE_BADGE,
    AUTH_STATE_LABELS,
    AuthDetector,
    AuthSession,
    AuthState,
    classify_auth_response,
    is_login_path,
)

__all__ = [
    "AuthSpec",
    "BaseProvider",
    "AuthenticationManager",
    "PROVIDERS",
    "CookieProvider",
    "BearerProvider",
    "JwtProvider",
    "HeaderProvider",
    "SessionValidator",
    "SessionValidationResult",
    "AuthSession",
    "AuthDetector",
    "AuthState",
    "AUTH_METHOD_LABELS",
    "AUTH_STATE_LABELS",
    "AUTH_STATE_BADGE",
    "classify_auth_response",
    "is_login_path",
]
