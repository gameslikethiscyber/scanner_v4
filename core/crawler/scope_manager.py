"""
Crawl scope management (SOP v4.0 Phase 2 — Advanced Smart Crawling).

A ``ScopeManager`` decides whether a discovered URL belongs to the configured
crawl scope, keeping the crawler ``on-target`` and preventing it from wandering
off to unrelated hosts or paths.

Supported scopes:
- ``domain``    the registrable domain + any subdomain (default),
- ``subdomain`` only the exact start host (optionally its subdomains),
- ``path``      only the start host and URLs under the start path.

Include / exclude sub-domain and path regex patterns are applied first and
act as an explicit override.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional
from urllib.parse import urlsplit

SCOPE_DOMAIN = "domain"      # registrable domain incl. subdomains
SCOPE_SUBDOMAIN = "subdomain"  # exact host (or its subdomains if enabled)
SCOPE_PATH = "path"          # exact host + path prefix
SCOPE_ALL = "all"            # any host (trusted/developer use only)


class ScopeManager:
    def __init__(self, start_url: str,
                 scope: str = SCOPE_DOMAIN,
                 include_subdomains: bool = False,
                 include_patterns: Optional[Iterable[str]] = None,
                 exclude_patterns: Optional[Iterable[str]] = None):
        self.start_url = start_url
        self.scope = (scope or SCOPE_DOMAIN).lower()
        self.include_subdomains = include_subdomains

        parts = urlsplit(start_url)
        self.base_scheme = (parts.scheme or "https").lower()
        self.base_host = (parts.hostname or "").lower()
        self.base_netloc = (parts.netloc or "").lower()
        self.base_path = parts.path or "/"
        self.base_domain = self._base_domain(self.base_host)

        self._includes = [re.compile(p) for p in (include_patterns or [])]
        self._excludes = [re.compile(p) for p in (exclude_patterns or [])]

    @staticmethod
    def _base_domain(host: str) -> str:
        labels = host.split(".")
        if len(labels) >= 2:
            return ".".join(labels[-2:])
        return host or ""

    def is_in_scope(self, url: str) -> bool:
        """Return True when ``url`` may be crawled under the current scope."""
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return False
        if not parts.hostname:
            return False
        path = parts.path or "/"
        host = parts.hostname.lower()

        # Explicit include patterns override everything (whitelist).
        for rx in self._includes:
            if rx.search(url):
                return True

        # Explicit exclude patterns always win.
        for rx in self._excludes:
            if rx.search(url):
                return False

        if self.scope == SCOPE_ALL:
            return True

        if not self._same_host(host):
            return False

        if self.scope == SCOPE_PATH:
            return path == self.base_path or path.startswith(
                self.base_path.rstrip("/") + "/"
            ) or (self.base_path == "/" and path.startswith("/"))

        # domain / subdomain
        return True

    def _same_host(self, host: str) -> bool:
        if self.scope == SCOPE_SUBDOMAIN and not self.include_subdomains:
            return host == self.base_host
        if host == self.base_host:
            return True
        if self.scope == SCOPE_DOMAIN or self.include_subdomains:
            base = self.base_domain
            if not base:
                return host == self.base_host
            return host == base or host.endswith("." + base)
        return host == self.base_host

    def describe(self) -> str:
        return (
            f"scope={self.scope} host={self.base_host}"
            f" include_subdomains={self.include_subdomains}"
            f" includes={len(self._includes)} excludes={len(self._excludes)}"
        )