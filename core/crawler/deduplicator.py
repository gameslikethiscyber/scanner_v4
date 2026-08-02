"""
De-duplication for crawled resources (SOP v4.0 Phase 2 — Advanced Smart
Crawling).

Three layers of de-duplication:

1. URL deduplication (on the normalised URL),
2. redirect deduplication (same URL resolving to an already-visited target),
3. content-hash deduplication (distinct URLs returning identical bodies).

All layers are swapped on a per-crawl basis so repeated ``crawl()`` calls start
clean.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from core.crawler.url_normalizer import URLNormalizer


class Deduplicator:
    """Peforms URL / redirect / content-hash de-duplication during a crawl."""

    def __init__(self, normalizer: Optional[URLNormalizer] = None):
        self._normalizer = normalizer or URLNormalizer()
        self.reset()

    def reset(self) -> None:
        self._seen_urls = set()
        self._seen_content = set()
        self._seen_redirect_targets = set()

    def seen_url(self, url: str) -> bool:
        return self._canon(url) in self._seen_urls

    def add_url(self, url: str) -> None:
        self._seen_urls.add(self._canon(url))

    def seen_content(self, text: str) -> bool:
        h = self._hash(text)
        return h in self._seen_content

    def add_content(self, text: str) -> None:
        self._seen_content.add(self._hash(text))

    def seen_redirect(self, target_url: str) -> bool:
        return self._canon(target_url) in self._seen_redirect_targets

    def add_redirect(self, target_url: str) -> None:
        self._seen_redirect_targets.add(self._canon(target_url))

    def _canon(self, url: str) -> str:
        return self._normalizer.normalize(url)

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.md5(text.encode("utf-8", errors="replace"),
                           usedforsecurity=False).hexdigest()

    @property
    def url_count(self) -> int:
        return len(self._seen_urls)