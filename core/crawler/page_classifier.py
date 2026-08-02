"""
Automatic page classification (SOP v4.0 Phase 2 - Advanced Smart Crawling).

Classify crawled pages by path + HTML signals so the attack-surface summary can
report how many login/admin/API/error pages were discovered. This feeds the
reporting layer (Phase 2) and will later sharpen reporting (Future Phase).
"""

from __future__ import annotations

from urllib.parse import urlsplit

_RULES = [
    ("API", ("/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/", "/endpoint",
             "?__=api", "api.", "/swagger", "/openapi")),
    ("Admin", ("/admin", "/administrator", "/wp-admin", "/manage/", "/panel/")),
    ("Login", ("/login", "/signin", "/sign-in", "/auth", "/logon", "?login")),
    ("Dashboard", ("/dashboard", "/home", "/portal", "/account/overview")),
    ("User Profile", ("/profile", "/account", "/member/", "/user/", "/me")),
    ("Search", ("/search", "/query", "/results", "/find")),
    ("Product", ("/products", "/product/", "/item/", "/catalog/", "/shop", "/store/")),
    ("Documentation", ("/docs", "/documentation", "/swagger", "/help", "/guide", "/manual")),
    ("Static Asset", ("/images/", "/css", "/javascript", "/assets/", "/uploads/")),
    ("Error Page", ("/404", "/error", "/notfound", "/500")),
]

_TEMPLATE_ORDER = ("error", "login", "admin", "api", "dashboard", "profile",
                   "search", "product", "documentation", "static", "home")


class PageClassifier:
    """Classify a page path into a human-readable page category."""

    def classify(self, url: str, soup=None, status_code: int = 200) -> str:
        path = urlsplit(url).path.lower()
        label = self.classify_path(path, status_code=status_code)
        if soup is not None and label in ("Other", "Home"):
            if soup.find("form"):
                if soup.find("input", attrs={"type": "password"}):
                    return "Login"
                return "Form"
        return label

    def classify_path(self, path: str, status_code: int = 200) -> str:
        if status_code == 404:
            return "Error Page"
        path = (path or "/").lower()
        for label, tokens in _RULES:
            if any(tok in path for tok in tokens):
                return label
        return "Other"

    def categorise(self, urls_and_pages) -> dict:
        counts: dict = {}
        for item in urls_and_pages:
            label = self.classify(item.get("url", ""),
                                  status_code=item.get("status") or 200)
            counts[label] = counts.get(label, 0) + 1
        return counts