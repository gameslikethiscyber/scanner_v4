"""
Session validation (SOP v4.0 Phase 1).

Validation only runs when authentication is enabled. Anonymous scans are
skipped entirely (``applicable = False``). When enabled, the validator probes
the target with the session attached and looks for the usual failure signals:

- HTTP 401 / 403 (unauthorized / blocked),
- a redirect back to a login page,
- a 200 response whose body is a login page (password field / login form).

On failure the caller shows a clear message and lets the user retry or continue
anonymously — authentication is never mandatory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class SessionValidationResult:
    valid: bool = False            # session accepted (or not applicable)
    applicable: bool = False       # True only when authentication is enabled
    status_code: int = 0
    classification: str = "unknown"
    redirected_to_login: bool = False
    reason: str = ""
    message: str = ""

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "applicable": self.applicable,
            "status_code": self.status_code,
            "classification": self.classification,
            "redirected_to_login": self.redirected_to_login,
            "reason": self.reason,
            "message": self.message,
        }


class SessionValidator:
    """Validate an authenticated session against a target before crawling."""

    def __init__(self, timeout: int = 10, max_probes: int = 2):
        self.timeout = timeout
        self.max_probes = max_probes

    def validate(self, auth: Any, session: Any, target: str,
                 protected_paths: Optional[List[str]] = None) -> SessionValidationResult:
        result = SessionValidationResult()
        method = getattr(auth, "method", "public")
        if auth is None or method == "public":
            result.applicable = False
            result.valid = True
            return result

        result.applicable = True
        # Probe with a fresh requests session so validation never mutates the
        # tracked crawl session with probe requests.
        try:
            import requests
            probe = requests.Session()
            auth.apply_to(probe)
        except Exception:
            probe = session

        from core.auth_manager import AuthDetector, classify_auth_response, is_login_path

        targets = [target]
        for p in (protected_paths or [])[:self.max_probes]:
            targets.append(target.rstrip("/") + p)

        for url in targets:
            try:
                resp = probe.get(url, timeout=self.timeout, allow_redirects=True)
            except Exception as exc:
                result.reason = f"Validation probe failed: {str(exc)[:200]}"
                result.valid = False
                result.classification = "error"
                result.message = self._message(result)
                return result

            result.status_code = getattr(resp, "status_code", 0)
            classification = classify_auth_response(url, resp)
            result.classification = classification.get("classification", "unknown")
            final_url = (getattr(resp, "url", "") or "").lower()
            result.redirected_to_login = is_login_path(final_url)

            login_body = False
            try:
                det = AuthDetector().analyze(
                    url=final_url,
                    html=(getattr(resp, "text", "") or ""),
                    status_code=result.status_code,
                )
                login_body = bool(det.has_password_field)
            except Exception:
                login_body = False

            if result.classification in ("unauthorized", "blocked"):
                result.reason = classification.get("reason", "Session rejected")
                result.valid = False
                result.message = self._message(result)
                return result
            if result.redirected_to_login or login_body:
                result.reason = "Session redirected to the login page (expired or invalid)"
                result.valid = False
                result.message = self._message(result)
                return result

            result.valid = True
            result.reason = "Session accepted"
            result.message = self._message(result)
            return result

        result.message = self._message(result)
        return result

    @staticmethod
    def _message(result: SessionValidationResult) -> str:
        if not result.applicable:
            return "No session validation performed (anonymous scan)."
        if result.valid:
            return "Session validated successfully."
        return result.reason or "Session validation failed."
