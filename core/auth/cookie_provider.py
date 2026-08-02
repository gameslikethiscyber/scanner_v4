"""
Cookie authentication provider (SOP v4.0 Phase 1).

Parses a cookie file (Netscape ``# Netscape HTTP Cookie File`` format or plain
``name=value`` lines / ``name=value; name2=value2`` strings) into an in-memory
``AuthSession``. Values are never written to reports or logs.
"""

from __future__ import annotations

from typing import List, Optional

from core.auth.base import AuthSpec, BaseProvider
from core.auth_manager import AuthSession


class CookieProvider(BaseProvider):
    name = "cookies"

    def build(self, spec: AuthSpec) -> AuthSession:
        auth = AuthSession(method="cookies")
        if spec.cookie_string:
            auth.set_cookies_from_string(spec.cookie_string, domain="")
        elif spec.cookie_file:
            self._ingest_text(auth, self._read_file(spec.cookie_file))
        return auth

    def _ingest_text(self, auth: AuthSession, text: str) -> None:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "\t" in line and len(line.split("\t")) >= 7:
                entry = self._parse_netscape_line(line)
                if entry:
                    auth.set_cookie(entry["name"], entry["value"], domain=entry["domain"])
                continue
            if "=" in line:
                name, _, value = line.partition("=")
                name = name.strip()
                value = value.strip()
                if name:
                    auth.set_cookie(name, value)

    @staticmethod
    def _parse_netscape_line(line: str) -> Optional[dict]:
        parts = [p.strip() for p in line.split("\t")]
        if len(parts) < 7:
            return None
        domain, _include_subdomains, _path, _secure, _expiry, name, value = parts[:7]
        if not name:
            return None
        return {"domain": domain, "name": name, "value": value}
