"""
JWT authentication provider (SOP v4.0 Phase 1).

Reads a JWT from a file (first non-empty line) or an inline value and builds an
in-memory ``AuthSession`` carrying it as an ``Authorization`` bearer token. The
token is redacted in every export.
"""

from __future__ import annotations

from core.auth.base import AuthSpec, BaseProvider
from core.auth_manager import AuthSession


class JwtProvider(BaseProvider):
    name = "jwt"

    def build(self, spec: AuthSpec) -> AuthSession:
        auth = AuthSession(method="jwt")
        token = (spec.token or "").strip() or self._read_first_token(spec.token_file)
        if token:
            auth.set_jwt_token(token)
        return auth
