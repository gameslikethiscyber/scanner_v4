"""
Link discovery from HTML (SOP v4.0 Phase 2 — Advanced Smart Crawling).

Extracts candidate URLs from an HTML document: anchors, form actions, canonical
links, meta-refresh redirect targets and ``<base>`` resolution. JavaScript is
limited to the *static* extraction the project already has (regex over inline
scripts and ``script src``) — no browser rendering.
"""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from core.js_analyzer import extract_urls_from_js


class LinkDiscovery:
    """Turn a parsed HTML document into a structured set of crawl hints."""

    def extract(self, soup: BeautifulSoup, base_url: str) -> Dict:
        """Return {links, forms, canonical, js_urls, meta_redirect}."""
        result = {
            "links": [],
            "forms": [],
            "canonical": None,
            "js_urls": [],
            "meta_redirect": None,
        }

        # Resolve against the explicit <base href> if one exists.
        href = ""
        base = soup.find("base", href=True)
        if base:
            href = base.get("href") or ""
            if href:
                result["canonical"] = href  # informative only

        link_base = urljoin(base_url, href) if href else base_url

        # Anchors (including nav menus).
        seen = set()
        for a in soup.find_all("a", href=True):
            raw = a.get("href")
            if not raw:
                continue
            full = urljoin(link_base, raw)
            if full in seen:
                continue
            seen.add(full)
            result["links"].append(full)
        # data-attribute routed links (static hint, cheap).
        for el in soup.find_all(attrs={
                "data-href": True, "data-url": True, "data-link": True}):
            for key in ("data-href", "data-url", "data-link"):
                raw = el.get(key)
                if raw:
                    full = urljoin(link_base, raw)
                    if full not in seen:
                        seen.add(full)
                        result["links"].append(full)

        # <link rel=canonical>
        canonical = soup.find("link", rel=re_l("canonical"), href=True)
        if canonical:
            result["canonical"] = urljoin(link_base, canonical.get("href"))

        # meta refresh -> redirect-like target (treat as a link, not followed).
        meta = soup.find("meta", attrs={"http-equiv": "refresh"})
        if meta:
            content = meta.get("content", "")
            url_part = content.split(";", 1)[-1] if ";" in content else content
            if "url=" in url_part:
                result["meta_redirect"] = urljoin(link_base, url_part.split("url=", 1)[1].strip())

        return result

    @staticmethod
    def extract_js(soup: BeautifulSoup, base_url: str) -> List[str]:
        """Static JS URL extraction: inline scripts + script src attributes."""
        urls: List[str] = []
        seen = set()
        # Inline scripts (static regex extraction only, no execution).
        for script in soup.find_all("script", src=False):
            if not script.string:
                continue
            for u in extract_urls_from_js(script.string, base_url):
                if u not in seen:
                    seen.add(u)
                    urls.append(u)
        return urls

    @staticmethod
    def extract_forms(soup: BeautifulSoup, base_url: str) -> List:
        """POST forms with filled sample field values (mirrors legacy logic)."""
        from core.crawler.forms_helper import extract_post_forms

        return extract_post_forms(soup, base_url)


def re_l(value: str):
    """Return a bs4 relaxed regex matcher for an attribute value."""
    import re

    def matches(val):
        if val is None:
            return False
        return re.search(value, val, re.IGNORECASE) is not None

    return matches