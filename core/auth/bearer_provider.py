"""
Bearer token authentication provider (SOP v4.0 Phase 1).

Reads a bearer token from a file (first non-empty line) or an inline value and
builds an in-memory ``AuthSession``. The token is applied as an
``Authorization: Bearer <token>`` header and is always redacted in exports.
"""

from __future__ import annotations

from core.auth.base import AuthSpec, BaseProvider
from core.auth_manager import AuthSession


class BearerProvider(BaseProvider):
    name = "bearer"

    def build(self, spec: AuthSpec) -> AuthSession:
        auth = AuthSession(method="bearer")
        token = (spec.token or "").strip() or self._read_first_token(spec.token_file)
        if token:
            auth.set_bearer_token(token)
        return auth
