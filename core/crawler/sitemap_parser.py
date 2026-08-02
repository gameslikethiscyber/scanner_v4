"""
sitemap.xml parsing (SOP v4.0 Phase 2 — Advanced Smart Crawling).

Downloads and parses `sitemap.xml` (and `sitemap:index`) documents, including
gzip-encoded payloads and nested sitemap indexes, and returns the merged list
of URLs for the crawl queue. Discovery is merged with the normal crawl and
de-duplicated by the queue/deduplicator.
"""

from __future__ import annotations

import gzip
import io
import logging
import re
from typing import Iterable, List, Optional, Set
from urllib.parse import urljoin, urlsplit

try:
    from xml.etree import cElementTree as ET
except ImportError:  # pragma: no cover
    from xml.etree import ElementTree as ET

logger = logging.getLogger("CSA_Scanner.Crawler.Sitemap")

_LOC = "{http://www.sitemaps.org/schemas/sitemap/0.9}loc"
_MAX_INDEX_DEPTH = 4


class SitemapParser:
    """Fetch + parse one or more sitemap sources into a URL set."""

    def __init__(self, timeout: float = 12, max_urls: int = 20000):
        self.timeout = timeout
        self.max_urls = max_urls

    def fetch(self, session, url: str, scope=None) -> Set[str]:
        """Fetch a sitemap (or sitemap index) and return discovered URLs."""
        return self._collect(session, url, scope=scope, depth=0)

    def _collect(self, session, url: str, scope, depth: int) -> Set[str]:
        if depth > _MAX_INDEX_DEPTH:
            return set()
        urls: Set[str] = set()
        try:
            resp = session.get(url, timeout=self.timeout, stream=True)
            if getattr(resp, "status_code", 0) != 200:
                return urls
            data = self._decode(resp)
            if not data:
                return urls
        except Exception as e:
            logger.debug("sitemap fetch failed %s: %s", url, e)
            return set()

        for node_url, is_index in self._iter_locs(data):
            if is_index:
                urls |= self._collect(session, node_url, scope, depth + 1)
                continue
            if len(urls) >= self.max_urls:
                break
            if self._looks_like_url(node_url):
                if scope is not None and not scope.is_in_scope(node_url):
                    continue
                urls.add(node_url)
        # Stop once over the cap (roughly).
        if len(urls) > self.max_urls:
            return set(list(urls)[: self.max_urls])
        return urls

    def _decode(self, resp) -> Optional[str]:
        raw = resp.content or b""
        if not raw:
            return None
        try:
            if _gz(raw):
                raw = gzip.decompress(raw)
        except OSError:
            pass
        for encoding in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                return raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode("utf-8", errors="replace")

    def _iter_locs(self, text: str):
        """Yield (url, is_index) pairs tolerating malformed documents."""
        try:
            root = ET.fromstring(text)
        except (ET.ParseError, ValueError):
            # Plain list of URLs or a malformed XML — fall back to <loc>
            for line in text.splitlines():
                m = re.search(r"<loc>\s*(.*?)\s*</loc>", line)
                if m and m.group(1).strip():
                    yield m.group(1).strip(), False
            # also derive from predicate content type
            return
        tag = root.tag
        is_index = tag.endswith("sitemapindex")
        for el in root.iter():
            if el.tag == _LOC and el.text:
                yield el.text.strip(), is_index

    @staticmethod
    def _looks_like_url(u: str) -> bool:
        parts = urlsplit(u)
        return parts.scheme in ("http", "https") and bool(parts.netloc)


def _gz(raw: bytes) -> bool:
    return raw[:2] == b"\x1f\x8b"