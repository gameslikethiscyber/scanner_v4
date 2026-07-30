import re
from urllib.parse import urljoin, urlparse
from typing import Set, List

from core.ssrf_guard import is_safe_url

LINKFINDER_PATTERNS = [
    r'(?:src|href|action|data-url|data-src|data-href|data-endpoint)\s*=\s*["\']([^"\']+)["\']',
    r'(?:url|uri|path|endpoint|route|api)\s*[:=]\s*["\']([^"\']+)["\']',
    r'(?:axios|fetch|XMLHttpRequest|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["\']([^"\']+)["\']',
    r'(?:from|import|require)\s*\(?\s*["\']([^"\']+)["\']',
    r'(?:baseURL|base_url|basePath|base_path)\s*[:=]\s*["\']([^"\']+)["\']',
    r'(?:location\.(?:href|pathname|hash|search))\s*=\s*["\']([^"\']+)["\']',
    r'(?:open|navigateTo|redirectTo)\s*\(\s*["\']([^"\']+)["\']',
    r'(?:resolve|reject)\s*\(\s*["\']([^"\']+)["\']',
    r'(?:controller|action)\s*[:=]\s*["\']([^"\']+)["\']',
    r'["\'](?:/[a-zA-Z0-9_\-/.?=&%+#]+)["\']',
    r"['](?:/[a-zA-Z0-9_\-/.?=&%+#]+)[']",
]

ABSOLUTE_PATH_RE = re.compile(r'^(https?://|//)')
RELATIVE_PATH_RE = re.compile(r'^/[a-zA-Z0-9_\-/.?=&%+#]*$')
PROTOCOL_RELATIVE_RE = re.compile(r'^//[a-zA-Z0-9._-]+')


def extract_urls_from_js(js_content: str, base_url: str) -> Set[str]:
    urls: Set[str] = set()
    markers: Set[str] = set()

    for pattern in LINKFINDER_PATTERNS:
        for match in re.finditer(pattern, js_content, re.IGNORECASE):
            candidate = match.group(1).strip()
            if not candidate:
                continue
            if candidate.startswith(('data:', 'javascript:', 'blob:', 'mailto:', 'tel:')):
                continue
            if len(candidate) < 2:
                continue
            if candidate.startswith(('{', '<', '[', '`')):
                continue
            markers.add(candidate)

    for candidate in markers:
        try:
            if ABSOLUTE_PATH_RE.match(candidate):
                if not is_safe_url(candidate):
                    continue
                urls.add(candidate)
            elif candidate.startswith('/'):
                full = urljoin(base_url, candidate)
                if is_safe_url(full):
                    urls.add(full)
            elif candidate.startswith('..') or candidate.startswith('.'):
                full = urljoin(base_url, candidate)
                if is_safe_url(full):
                    urls.add(full)
            elif candidate.startswith('//'):
                full = 'https:' + candidate
                if is_safe_url(full):
                    urls.add(full)
            elif not candidate.startswith(('#', '?')):
                if '/' in candidate and '.' in candidate:
                    full = urljoin(base_url, candidate)
                    if is_safe_url(full):
                        urls.add(full)
        except Exception:
            continue

    return urls


def is_js_url(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    return path.endswith(('.js', '.mjs', '.jsx'))
