"""
HTML form extraction (SOP v4.0 Phase 2 — Advanced Smart Crawling).

Shared by the HTTP crawler and the link discoverer. Mirrors the legacy
form/field-filling behaviour so POST scan coverage is unchanged.
"""

from __future__ import annotations

from typing import List
from urllib.parse import urljoin

from bs4 import BeautifulSoup


def extract_post_forms(soup: BeautifulSoup, base_url: str) -> List[dict]:
    """Return a list of ``{'url': ..., 'fields': {...}}`` for POST forms."""
    forms: List[dict] = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method") or "get").lower()
        if method != "post":
            continue
        full_url = urljoin(base_url, action)
        fields = {}
        for input_tag in form.find_all(["input", "textarea", "select"]):
            name = input_tag.get("name")
            if not name:
                continue
            fields[name] = _generate_value(input_tag)
        if fields:
            forms.append({"url": full_url, "fields": fields})
    return forms


def _generate_value(tag) -> str:
    input_type = (tag.get("type") or "text").lower()
    name = (tag.get("name") or "").lower()
    if tag.get("value"):
        return tag.get("value")
    if input_type == "email" or "email" in name:
        return "test@example.com"
    if input_type == "password" or "password" in name or "pass" in name:
        return "Password123!"
    if "phone" in name or "tel" in name:
        return "01000000000"
    if "date" in name:
        return "2024-01-01"
    if "number" in name or "age" in name:
        return "25"
    if input_type == "checkbox":
        return "on"
    if input_type == "radio":
        return tag.get("value", "on")
    if tag.name == "select":
        options = tag.find_all("option")
        if options:
            return options[0].get("value", "")
        return "1"
    if "search" in name or name == "q":
        return "test"
    if any(k in name for k in ("comment", "message", "content")):
        return "This is a test message."
    return "test"