"""
Custom HTTP header authentication provider (SOP v4.0 Phase 1).

Builds an in-memory ``AuthSession`` from repeatable ``"Name: Value"`` header
strings (e.g. ``Authorization: ApiKey xxx``). Header values are applied to every
request and are redacted in exports.
"""

from __future__ import annotations

from typing import Dict

from core.auth.base import AuthSpec, BaseProvider
from core.auth_manager import AuthSession


class HeaderProvider(BaseProvider):
    name = "headers"

    def build(self, spec: AuthSpec) -> AuthSession:
        pairs: Dict[str, str] = {}
        for header in (spec.headers or []):
            if ":" not in header:
                continue
            name, _, value = header.partition(":")
            name = name.strip()
            value = value.strip()
            if name and value:
                pairs[name] = value
        auth = AuthSession(method="headers")
        auth.configure_headers(pairs)
        return auth
