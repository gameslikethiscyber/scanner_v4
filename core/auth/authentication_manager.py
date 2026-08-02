"""
AuthenticationManager — standalone orchestration of the optional authentication
providers (SOP v4.0 Phase 1).

Authentication is an opt-in feature. Without an ``AuthSpec`` the manager is a
no-op and the scan stays anonymous (the default, unchanged behaviour). When an
``AuthSpec`` is provided the manager:

1. builds an in-memory ``AuthSession`` via the matching provider,
2. attaches it to the transport session,
3. optionally validates it (only when authentication is enabled).

Scanners never contain authentication logic; they receive the configured
session transparently.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.auth.base import AuthSpec, BaseProvider
from core.auth.bearer_provider import BearerProvider
from core.auth.cookie_provider import CookieProvider
from core.auth.header_provider import HeaderProvider
from core.auth.jwt_provider import JwtProvider
from core.auth.session_validator import SessionValidationResult, SessionValidator

logger = logging.getLogger("SeaScanner.Auth")

PROVIDERS: Dict[str, BaseProvider] = {
    "cookies": CookieProvider(),
    "bearer": BearerProvider(),
    "jwt": JwtProvider(),
    "headers": HeaderProvider(),
}


class AuthenticationManager:
    """Facade over the optional authentication providers."""

    def __init__(self):
        self.validator = SessionValidator()

    def is_supported(self, auth_type: str) -> bool:
        return auth_type in PROVIDERS

    def build(self, spec: Optional[AuthSpec]) -> Optional[Any]:
        """Build an AuthSession from an AuthSpec. Returns None for no auth."""
        if spec is None or not getattr(spec, "enabled", False):
            return None
        auth_type = getattr(spec, "type", "cookies") or "cookies"
        if auth_type not in PROVIDERS:
            raise ValueError(f"Unsupported authentication type: {auth_type!r}")
        auth = PROVIDERS[auth_type].build(spec)
        if auth is None or not self._has_credentials(auth):
            raise ValueError(
                f"No valid {auth_type} credentials were provided "
                f"(check the file/path exists and is non-empty)."
            )
        return auth

    @staticmethod
    def _has_credentials(auth: Any) -> bool:
        """True only when the built session actually carries credentials."""
        method = getattr(auth, "method", "public") or "public"
        if method == "public":
            return False
        if method in ("bearer", "jwt"):
            return bool(getattr(auth, "token", ""))
        if method == "cookies":
            return bool(getattr(auth, "cookies", None))
        if method == "headers":
            return bool(getattr(auth, "extra_headers", None))
        return False

    def apply_to(self, auth: Optional[Any], session: Optional[Any]) -> None:
        """Attach an AuthSession to a transport session (no-op for anonymous)."""
        if auth is not None and session is not None:
            try:
                auth.apply_to(session)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Could not attach auth session: %s", exc)

    def validate(self, auth: Optional[Any], session: Optional[Any], target: str,
                 protected_paths: Optional[list] = None) -> SessionValidationResult:
        """Validate an authenticated session. Anonymous scans are skipped."""
        if auth is None:
            return SessionValidationResult(applicable=False, valid=True)
        return self.validator.validate(auth, session, target, protected_paths)

    def activate(self, auth: Optional[Any], session: Optional[Any], scan_result: Any = None) -> None:
        """Apply an AuthSession to a session and record it on the ScanResult."""
        self.apply_to(auth, session)
        if scan_result is not None and auth is not None:
            try:
                scan_result.set_auth_session(auth)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Could not record auth session: %s", exc)

    def mark_invalid(self, auth: Optional[Any]) -> None:
        """Flag an AuthSession as invalid after failed validation (best-effort).

        Cookies map to an expired session; token-based methods map to an
        invalid token so the final report reflects the failed session instead
        of claiming the scan was authenticated.
        """
        if auth is None or getattr(auth, "method", None) in (None, "public"):
            return
        try:
            if auth.method == "cookies":
                auth.mark_expired()
            else:
                auth.mark_token_invalid()
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Could not mark auth session invalid: %s", exc)
