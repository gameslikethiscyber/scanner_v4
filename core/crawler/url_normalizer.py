"""
URL normalization (SOP v4.0 Phase 2 — Advanced Smart Crawling).

Normalised URLs are used for deduplication so the same resource is never
scanned twice. Normalisation is cheap and lossless enough for crawling:

- fragments (``#...``) are dropped,
- default ports (80/443) are removed,
- hosts are lower-cased,
- duplicate slashes and dot-segments are collapsed,
- common tracking parameters are stripped,
- empty query parameters are dropped.
"""

from __future__ import annotations

import posixpath
import re
from typing import Iterable, Optional
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlparse,
    urlsplit,
    urlunsplit,
)

# Hosting / marketing / analytics parameters that carry no scan value.
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_campaignid", "utm_contentid",
    "fbclid", "gclid", "gclsrc", "dclid", "gelid", "msclkid", "wbraid", "gbraid",
    "igshid", "mc_cid", "mc_eid", "yclid", "li_fat_id", "snowplow_duid",
    "ref", "referrer", "source", "campaign", "ref_src", "ref_url",
    "_ga", "_gl", "_gid", "_hsenc", "_hsmi", "spm", "al_applink_data",
    "affiliate", "aff_id", "partner", "subid", "ads_campaign_id",
}

# Ports that can be dropped without changing the resource.
_DEFAULT_PORT = {"http": "80", "https": "443"}


class URLNormalizer:
    """Normalise and canonicalise URLs for de-duplicated crawling."""

    def normalize(self, url: str, base_url: Optional[str] = None) -> str:
        """Return a canonical string, resolving relative URLs against ``base_url``.

        If ``url`` has no host (a bare path/relative reference) it is joined to
        ``base_url`` first. If it still cannot be made absolute it is returned
        unchanged (safe excess path for relative-only callers).
        """
        if not url:
            return url
        raw = url.strip()
        if base_url:
            raw = urljoin(base_url, raw)
        parts = urlsplit(raw)

        # Nothing to canonicalise if we lack a scheme/host.
        if not parts.scheme or not parts.netloc:
            return raw

        scheme = parts.scheme.lower()
        netloc = self._normalize_netloc(parts.netloc)
        path = self._normalize_path(parts.path)
        query = self._normalize_query(parts.query)
        # Fragments are never part of the resource identity.
        fragment = ""

        if scheme not in ("http", "https"):
            # Preserve arbitrary schemes (file:, ftp:) but still canonicalise
            # the rest. Returned purely for robustness of the resolver.
            return urlunsplit((scheme, netloc, path, query, fragment))

        return urlunsplit((scheme, netloc, path, query, fragment))

    def _normalize_netloc(self, netloc: str) -> str:
        host = netloc.lower()
        if host.endswith(":443"):
            return host[:-4]
        if host.endswith(":80"):
            return host[:-3]
        return host

    def _normalize_path(self, path: str) -> str:
        if not path:
            return "/"
        keep_trailing = len(path) > 1 and path.endswith("/")
        cleaned = posixpath.normpath(path)
        if not cleaned.startswith("/"):
            cleaned = "/" + cleaned
        has_ext = "." in cleaned.rsplit("/", 1)[-1]
        if keep_trailing and not cleaned.endswith("/") and not has_ext:
            cleaned += "/"
        return cleaned

    def _normalize_query(self, query: str) -> str:
        if not query:
            return ""
        kept = []
        for key, value in parse_qsl(query, keep_blank_values=True):
            if key.lower() in TRACKING_PARAMS:
                continue
            if value == "":
                continue
            kept.append((key, value))
        if not kept:
            return ""
        return urlencode(kept, doseq=True)

    # -- helpers reused by the crawler ------------------------------------
    @staticmethod
    def strip_fragment(url: str) -> str:
        return url.split("#", 1)[0]

    @staticmethod
    def host_of(url: str) -> str:
        return (urlsplit(url).hostname or "").lower()

    @staticmethod
    def same_netloc(url_a: str, url_b: str) -> bool:
        return (urlsplit(url_a).netloc or "").lower() == \
               (urlsplit(url_b).netloc or "").lower()


def normalize_url(url: str, base_url: Optional[str] = None) -> str:
    return URLNormalizer().normalize(url, base_url)