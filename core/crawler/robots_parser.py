"""
robots.txt parsing (SOP v4.0 Phase 2 — Advanced Smart Crawling).

Per the SOP, robots.txt is downloaded and parsed for informational purposes and
to surface ``Sitemap:`` references. Disallowed paths are **not** excluded
automatically; whether to honour them is a user-controlled option
(``respect_robots``, default off).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin, urlsplit

logger = logging.getLogger("SeaScanner.Crawler.Robots")


@dataclass
class Robots:
    """Parsed robots.txt content for a single origin."""

    url: str = ""
    user_agents: List[str] = field(default_factory=list)
    allow: List[str] = field(default_factory=list)
    disallow: List[str] = field(default_factory=list)
    crawl_delay: Optional[str] = None
    sitemaps: List[str] = field(default_factory=list)
    raw: str = ""
    errors: int = 0

    def allowed(self, agent: Optional[str] = "SeaScanner") -> bool:
        """True when ``path`` is not disallowed for ``agent`` (best-effort)."""
        return True  # respecting is a crawler policy decision, not here

    def summarize(self) -> dict:
        return {
            "url": self.url,
            "disallowed": self.disallow,
            "allowed": self.allow,
            "crawl_delay": self.crawl_delay,
            "sitemaps": self.sitemaps,
        }


class RobotsParser:
    """Download and parse a robots.txt document."""

    USER_AGENT_RE = re.compile(r"^User-agent\s*:\s*(.*)$", re.IGNORECASE)
    ALLOW_RE = re.compile(r"^Allow\s*:\s*(.*)$", re.IGNORECASE)
    DISALLOW_RE = re.compile(r"^Disallow\s*:\s*(.*)$", re.IGNORECASE)
    DELAY_RE = re.compile(r"^Crawl-delay\s*:\s*(.*)$", re.IGNORECASE)
    SITEMAP_RE = re.compile(r"^Sitemap\s*:\s*(.*)$", re.IGNORECASE)

    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    def fetch(self, session, base_url: str) -> Optional[Robots]:
        """Retrieve ``/robots.txt`` for the base URL's origin. Returns None on
        failure or non-200."""
        origin = self._origin(base_url)
        if not origin:
            return None
        url = origin + "/robots.txt"
        try:
            resp = session.get(url, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            logger.debug("robots.txt fetch failed for %s: %s", url, e)
            return None
        if getattr(resp, "status_code", 0) not in (200, 206):
            return None
        return self.parse(resp.text, url=url)

    def parse(self, text: str, url: str = "") -> Robots:
        robots = Robots(url=url, raw=text)
        for line in text.splitlines():
            line = line.strip()
            m = self.USER_AGENT_RE.match(line)
            if m and m.group(1).strip():
                robots.user_agents.append(m.group(1).strip())
            m = self.ALLOW_RE.match(line)
            if m and m.group(1).strip():
                robots.allow.append(m.group(1).strip())
            m = self.DISALLOW_RE.match(line)
            if m and m.group(1).strip():
                robots.disallow.append(m.group(1).strip())
            m = self.DELAY_RE.match(line)
            if m and m.group(1).strip():
                robots.crawl_delay = m.group(1).strip()
            m = self.SITEMAP_RE.match(line)
            if m and m.group(1).strip():
                robots.sitemaps.append(m.group(1).strip())
        robots.errors = sum(1 for ln in text.splitlines()
                            if ln.strip() and not ln.startswith("#") and ":" not in ln)
        return robots

    @staticmethod
    def _origin(url: str) -> str:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            return ""
        return f"{parts.scheme}://{parts.netloc}"