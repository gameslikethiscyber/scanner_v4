"""
Secret redaction utilities.

Security requirements (SOP Phase 13):
- Never log passwords, save passwords in reports, save cookies unless
  explicitly requested, export tokens in HTML/PDF, or display secrets in logs.
- Automatically redact cookies, JWTs, Authorization headers, and API keys.

Used by the reporter, session state, and console output.
"""

import re
from typing import Any, Dict, List

REDACTED = "****************"
REDACTED_SHORT = "********"

_JWT_PATTERN = re.compile(
    r'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}'
)
_BEARER_PATTERN = re.compile(
    r'(?i)(authorization|proxy-authorization)\s*[:=]\s*bearer\s+([^\s,;]+)'
)
_COOKIE_PAIR = re.compile(
    r'(?i)(((?:[a-z0-9_.-]*session[a-z0-9_.-]*|jsessionid|phpsessid|aspnet'
    r'sessionid|asp\.net_sessionid|sid|csrftoken|xsrf[-_]?token|auth[-_]?token'
    r'|access[-_]?token|refresh[-_]?token|laravel_session|connect\.sid|'
    r'__requestverificationtoken|auth0|firebase[a-z]*idtoken|idtoken|'
    r'access_token)\s*=\s*)([^;\s]+))'
)
_KEY_VALUE_PATTERN = re.compile(
    r'(?i)((?:api[-_]?key|apikey|client[-_]?secret|secret[-_]?key|'
    r'password|passwd|token|auth[-_]?token|access[-_]?token|refresh[-_]?token)'
    r'\s*[:=]\s*["\']?)([a-z0-9._/\-+~]{6,})["\']?'
)

SECRET_KEY_TERMS = (
    'password', 'passwd', 'pass', 'secret', 'token', 'authorization',
    'cookie', 'set-cookie', 'api-key', 'apikey', 'api_key', 'auth',
    'bearer', 'jwt', 'session', 'credential', 'key',
)


def is_secret_key(name: Any) -> bool:
    """Return True when a field/header/cookie name should be redacted."""
    if name is None:
        return False
    n = str(name).strip().lower().replace(' ', '_').replace('-', '_')
    for term in SECRET_KEY_TERMS:
        if term in n:
            return True
    return False


def redact_value(value: Any) -> str:
    """Redact a single sensitive value entirely."""
    if value is None:
        return REDACTED
    s = str(value)
    if len(s) <= 4:
        return REDACTED_SHORT
    return REDACTED


def redact_text(text: Any) -> str:
    """Redact JWTs, bearer tokens, cookie pairs, and secret key=value pairs."""
    if text is None:
        return ""
    s = str(text)
    s = _JWT_PATTERN.sub(REDACTED, s)
    s = _BEARER_PATTERN.sub(lambda m: f"{m.group(1)}: {REDACTED}", s)
    s = _COOKIE_PAIR.sub(lambda m: f"{m.group(2)}{REDACTED}", s)
    s = _KEY_VALUE_PATTERN.sub(lambda m: f"{m.group(1)}{REDACTED}", s)
    return s


def redact_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Return headers with sensitive values redacted."""
    if not headers:
        return dict(headers or {})
    out = {}
    for k, v in headers.items():
        if is_secret_key(k):
            out[k] = redact_value(v)
        else:
            out[k] = redact_text(v)
    return out


def redact_dict(data: Any) -> Any:
    """Deep-redact a structure, preserving keys but masking secret values."""
    if isinstance(data, dict):
        return {
            k: redact_dict(v) if not is_secret_key(k) else redact_value(v)
            for k, v in data.items()
        }
    if isinstance(data, (list, tuple, set)):
        return [redact_dict(i) for i in data]
    if isinstance(data, str):
        return redact_text(data)
    return data


def redact_url(url: Any) -> str:
    """Redact sensitive query-string parameters from a URL."""
    if not url:
        return str(url or "")
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
    parsed = urlparse(str(url))
    qs = [(k, redact_value(v) if is_secret_key(k) else v)
          for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunparse(parsed._replace(query=urlencode(qs)))
