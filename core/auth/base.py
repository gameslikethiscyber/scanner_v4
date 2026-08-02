"""
Shared contracts for the optional authentication providers (SOP v4.0 Phase 1).

Authentication is optional and never changes the default anonymous workflow.
Each provider builds an in-memory ``AuthSession`` (defined in
``core.auth_manager``) from a user-supplied ``AuthSpec``. Secrets are kept in
memory only and are always redacted when exported.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AuthSpec:
    """A user-supplied authentication description.

    Exactly one source is used depending on ``type``:

    - ``cookies``  -> ``cookie_file`` (Netscape or ``name=value`` lines) or ``cookie_string``
    - ``bearer``   -> ``token_file`` or ``token``
    - ``jwt``      -> ``token_file`` or ``token``
    - ``headers``  -> ``headers`` (list of ``"Name: Value"`` strings, repeatable)
    """

    type: str = "cookies"                 # cookies | bearer | jwt | headers
    cookie_file: str = ""
    cookie_string: str = ""
    token_file: str = ""
    token: str = ""
    headers: List[str] = field(default_factory=list)
    validate: bool = True                 # run session validation when enabled

    @property
    def enabled(self) -> bool:
        return bool(self.cookie_file or self.cookie_string or self.token_file
                    or self.token or self.headers)

    def describe(self) -> str:
        return self.type


class BaseProvider:
    """Interface for an authentication provider."""

    name: str = "base"

    def build(self, spec: AuthSpec) -> Any:
        """Return an AuthSession configured from ``spec`` (or a partial one)."""
        raise NotImplementedError

    # -- file helpers ------------------------------------------------------
    @staticmethod
    def _read_first_token(path: str) -> str:
        """Return the first non-empty, non-comment line of a credentials file."""
        raw = _read_credentials_file(path)
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return line
        return ""

    @staticmethod
    def _read_file(path: str) -> str:
        return _read_credentials_file(path)


def _read_credentials_file(path: str) -> str:
    """Read a credentials file, raising ValueError with a clear message on failure."""
    if not path:
        raise ValueError("No authentication file specified.")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        raise ValueError(f"Could not read authentication file '{path}': {exc}") from exc
