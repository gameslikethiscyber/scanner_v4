"""
Authentication Awareness & Authenticated Scanning System.

Optional, in-memory, backward-compatible authentication support modeled on
commercial scanners (Burp Suite, OWASP ZAP, Acunetix, Nessus):

  Phase 1  - Authentication detection with a confidence score.
  Phase 2  - Decision engine: keep scanning public pages and measure coverage.
  Phase 4  - Session cookie authentication (in-memory only).
  Phase 5  - Bearer token authentication (JWT / OAuth2 / API keys).
  Phase 6  - Reusable login profiles.
  Phase 7  - Browser session import (Chrome / Edge / Firefox / Brave).
  Phase 8  - Authenticated crawl + session refresh from Set-Cookie.
  Phase 11 - New execution states (AUTH REQUIRED, AUTHENTICATED, ...).
  Phase 15 - Extension points for scheduled / SSO / MFA / API providers.

All secrets remain in memory and are never exported.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.secrets_redactor import REDACTED, redact_text, is_secret_key

# ---------------------------------------------------------------------------
# Execution / session states (Phase 11)
# ---------------------------------------------------------------------------

class AuthState(Enum):
    NONE = "none"
    AUTH_REQUIRED = "auth_required"
    AUTHENTICATED = "authenticated"
    PUBLIC_ONLY = "public_only"
    SESSION_EXPIRED = "session_expired"
    LOGIN_FAILED = "login_failed"
    TOKEN_INVALID = "token_invalid"


AUTH_STATE_LABELS = {
    AuthState.NONE: "No Authentication",
    AuthState.AUTH_REQUIRED: "Auth Required",
    AuthState.AUTHENTICATED: "Authenticated",
    AuthState.PUBLIC_ONLY: "Public Only",
    AuthState.SESSION_EXPIRED: "Session Expired",
    AuthState.LOGIN_FAILED: "Login Failed",
    AuthState.TOKEN_INVALID: "Token Invalid",
}

AUTH_METHOD_LABELS = {
    'public': 'Anonymous',
    'cookies': 'Session Cookies',
    'bearer': 'Bearer Token',
    'jwt': 'JWT Token',
    'headers': 'Custom Headers',
    'login': 'Configured Login',
    'browser': 'Browser Session',
}

AUTH_STATE_BADGE = {
    'none': 'info', 'auth_required': 'warning', 'authenticated': 'safe',
    'public_only': 'info', 'session_expired': 'warning',
    'login_failed': 'critical', 'token_invalid': 'critical',
}

# ---------------------------------------------------------------------------
# Indicators (Phase 1)
# ---------------------------------------------------------------------------

LOGIN_SEGMENTS = {
    'login', 'log-in', 'signin', 'sign-in', 'sign_in', 'auth',
    'authenticate', 'authorize', 'oauth', 'idp', 'sso', 'connect', 'cas',
}

LOGIN_PATH_PATTERNS = (
    r'/login', r'/signin', r'/sign-in', r'/sign_in', r'/auth',
    r'/account/login', r'/user/login', r'/admin/login', r'/session/login',
    r'/authenticate', r'/oauth', r'/connect', r'/idp', r'/sso', r'/cas',
    r'/portal/login',
)

SESSION_COOKIE_NAMES = {
    'phpsessid', 'jsessionid', 'asp.net_sessionid', 'aspnetsessionid',
    'sessionid', 'session', 'sid', 'connect.sid', 'laravel_session',
    '_wp_session', 'wordpress_logged_in', 'auth_token', 'csrftoken',
    'csrf-token', 'xsrf-token', 'idtoken', 'access_token', 'refresh_token',
    'auth0', 'token',
}

FRAMEWORK_PATTERNS = (
    (r'laravel_session|csrf_token[^>]{0,80}laravel', 'Laravel'),
    (r'django.contrib.auth|csrftoken|django-session|__admin__', 'Django'),
    (r'__requestverificationtoken|aspnetidentity|x-aspnet-version', 'ASP.NET Identity'),
    (r'spring security|spring_security|springboot|jsessionid|_csrf', 'Spring Security'),
    (r'nextauth|next-auth', 'NextAuth'),
    (r'auth0|auth0\.com', 'Auth0'),
    (r'__clerk_db_session|clerk\.js|clerk-jwt', 'Clerk'),
    (r'firebaseapp|firebaseauth|firebase.*token', 'Firebase Auth'),
    (r'keycloak', 'Keycloak'),
    (r'okta', 'Okta'),
    (r'azuread|logine\.microsoftonline', 'Azure AD'),
)

_PASSWORD_INPUT_RE = re.compile(r'<input[^>]*type\s*=\s*["\']?password["\']?', re.I)
_SIGNIN_TEXT_RE = re.compile(r'(sign\s*in|log\s*in|signin|login|sign-in|log-in)')
_FORM_RE = re.compile(r'<form[^>]*>.*?</form>', re.I | re.S)


def is_login_path(url: str) -> bool:
    """Return True when a URL path looks like an authentication endpoint."""
    if not url:
        return False
    from urllib.parse import urlparse
    path = (urlparse(url).path or '').lower()
    segments = {s for s in path.split('/') if s}
    if segments & LOGIN_SEGMENTS:
        return True
    return any(re.search(p, path) for p in LOGIN_PATH_PATTERNS)


def classify_auth_response(url: str, response) -> Dict[str, Any]:
    """Classify a single HTTP response from an authentication perspective."""
    code = getattr(response, 'status_code', None) or 0
    redirect_urls = []
    for h in (getattr(response, 'history', None) or []):
        try:
            redirect_urls.append(h.url)
        except Exception:
            pass
    try:
        if getattr(response, 'url', None):
            redirect_urls.append(response.url)
    except Exception:
        pass

    redirected_to_login = any(is_login_path(u) for u in redirect_urls)

    if code in (401, 407):
        return {'url': url, 'status': code, 'classification': 'unauthorized',
                'reason': f"HTTP {code} Unauthorized"}
    if code == 403:
        return {'url': url, 'status': code, 'classification': 'blocked',
                'reason': "HTTP 403 Forbidden"}
    if code in (301, 302, 303, 307, 308):
        dest = redirect_urls[-1] if redirect_urls else ''
        if redirected_to_login or is_login_path(dest):
            return {'url': url, 'status': code, 'classification': 'redirected',
                    'reason': f"Redirect to login ({dest})"}
        return {'url': url, 'status': code, 'classification': 'redirected',
                'reason': f"Redirect to {dest}"}
    if code == 200:
        return {'url': url, 'status': code, 'classification': 'accessible',
                'reason': 'OK'}
    return {'url': url, 'status': code, 'classification': 'unknown',
            'reason': f"HTTP {code}"}


# ---------------------------------------------------------------------------
# Detection (Phase 1)
# ---------------------------------------------------------------------------

@dataclass
class AuthDetectionResult:
    detected: bool = False
    confidence: int = 0
    reasons: List[str] = field(default_factory=list)
    indicators: Dict[str, List[str]] = field(default_factory=dict)
    framework: str = ""
    login_urls: List[str] = field(default_factory=list)
    has_password_field: bool = False
    redirects_to_login: bool = False
    protected_status: Optional[int] = None
    session_cookie_created: bool = False

    def merge(self, other: 'AuthDetectionResult') -> 'AuthDetectionResult':
        """Combine signals from multiple probes."""
        self.reasons = list(dict.fromkeys(self.reasons + other.reasons))
        for k, v in other.indicators.items():
            self.indicators.setdefault(k, [])
            for item in v:
                if item not in self.indicators[k]:
                    self.indicators[k].append(item)
        self.confidence = max(self.confidence, other.confidence)
        self.has_password_field = self.has_password_field or other.has_password_field
        self.redirects_to_login = self.redirects_to_login or other.redirects_to_login
        if other.protected_status is not None:
            self.protected_status = other.protected_status
        self.session_cookie_created = self.session_cookie_created or other.session_cookie_created
        if other.framework:
            self.framework = self.framework or other.framework
        for u in other.login_urls:
            if u not in self.login_urls:
                self.login_urls.append(u)
        self.detected = self.confidence >= 50 or self.has_password_field
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            'detected': self.detected,
            'confidence': self.confidence,
            'reasons': self.reasons[:8],
            'indicators': {k: v[:8] for k, v in self.indicators.items()},
            'framework': self.framework,
            'login_urls': self.login_urls[:5],
            'has_password_field': self.has_password_field,
            'redirects_to_login': self.redirects_to_login,
            'protected_status': self.protected_status,
            'session_cookie_created': self.session_cookie_created,
        }


class AuthDetector:
    """Detect authentication requirements using HTML, URL, HTTP, and framework clues."""

    DEFAULT_LOGIN_PATHS = (
        '/login', '/signin', '/auth/login', '/account/login', '/user/login',
        '/admin/login',
    )

    def __init__(self, session=None):
        self.session = session

    def analyze(self, url: str = "", html: str = "", headers: Optional[Dict] = None,
                status_code: Optional[int] = None,
                redirect_urls: Optional[List[str]] = None,
                response_cookies: Optional[list] = None) -> AuthDetectionResult:
        result = AuthDetectionResult()
        reasons = []
        indicators: Dict[str, List[str]] = {'html': [], 'url': [], 'http': [], 'framework': [], 'session': []}
        score = 0

        # ---- URL indicators ----
        path = (url or "").lower()
        segments = {s for s in path.split('/') if s}
        if segments & LOGIN_SEGMENTS:
            score += 15
            indicators['url'].append('authentication endpoint path')
            reasons.append("Authentication endpoint detected in URL")

        # ---- HTTP indicators ----
        if status_code in (401, 407):
            score += 30
            indicators['http'].append(f"HTTP {status_code} Unauthorized")
            reasons.append(f"HTTP {status_code} Unauthorized response")
            result.protected_status = status_code
        elif status_code == 403:
            score += 25
            indicators['http'].append("HTTP 403 Forbidden")
            reasons.append("HTTP 403 Forbidden response")
            result.protected_status = status_code

        headers = headers or {}
        ww_auth = None
        for k, v in headers.items():
            if k.lower() == 'www-authenticate':
                ww_auth = str(v)
        if ww_auth:
            score += 20
            indicators['http'].append('WWW-Authenticate header')
            reasons.append("WWW-Authenticate header present")

        redirect_urls = redirect_urls or []
        if any(is_login_path(u) for u in redirect_urls):
            score += 20
            result.redirects_to_login = True
            indicators['http'].append('redirect to login page')
            reasons.append("Redirect to login page detected")

        # ---- Session cookie indicator ----
        session_cookie_seen = False
        for c in (response_cookies or []):
            name = str(getattr(c, 'name', c) if not isinstance(c, dict) else c.get('name', '')).lower()
            if name in SESSION_COOKIE_NAMES or 'session' in name:
                session_cookie_seen = True
                break
        if session_cookie_seen:
            score += 10
            result.session_cookie_created = True
            indicators['session'].append('session cookie created')
            reasons.append("Session cookie created")

        # ---- HTML indicators ----
        if html:
            html_signals = self._analyze_html(html, result)
            for label, points, reason in html_signals:
                score += points
                indicators['html'].append(label)
                reasons.append(reason)

        # ---- Framework indicators ----
        text_bucket = " ".join([
            str(html or ''),
            str(ww_auth or ''),
            str(headers.get('Server', '')),
            str(headers.get('X-Powered-By', '')),
            str(headers.get('X-AspNet-Version', '')),
        ]).lower()
        for pattern, fw in FRAMEWORK_PATTERNS:
            if re.search(pattern, text_bucket):
                score += 15
                result.framework = fw
                indicators['framework'].append(fw)
                reasons.append(f"{fw} framework detected")
                break

        result.confidence = min(100, score)
        result.reasons = list(dict.fromkeys(reasons))
        result.indicators = indicators
        result.login_urls = [u for u in redirect_urls if is_login_path(u)]
        result.detected = result.confidence >= 50 or result.has_password_field
        return result

    def _analyze_html(self, html: str, result: AuthDetectionResult) -> List[Tuple[str, int, str]]:
        signals: List[Tuple[str, int, str]] = []

        if _PASSWORD_INPUT_RE.search(html):
            result.has_password_field = True
            signals.append(('password field', 25, "Password field detected"))

        # Login form detection (a <form> containing a password input)
        login_form = False
        for m in _FORM_RE.finditer(html):
            if _PASSWORD_INPUT_RE.search(m.group(0)):
                login_form = True
                break
        if login_form:
            signals.append(('login form', 20, "Login form detected"))

        # Sign-in / login buttons or links
        text = html.lower()
        if re.search(r'<(?:button|a)\b[^>]*>[^<]*(?:sign\s*in|log\s*in|login|sign-in|log-in)[^<]*</(?:button|a)>', html, re.I):
            signals.append(('sign-in control', 10, "Sign in control detected"))
        elif _SIGNIN_TEXT_RE.search(text) and result.has_password_field:
            signals.append(('sign-in text', 5, "Sign-in wording present"))

        return signals

    def probe(self, base_url: str, session=None, timeout: int = 10,
              max_paths: int = 3) -> AuthDetectionResult:
        """Perform lightweight live probes of the base URL and common login paths."""
        import requests
        session = session or self.session or requests.Session()
        combined = AuthDetectionResult()
        targets = [base_url] + [base_url.rstrip('/') + p for p in self.DEFAULT_LOGIN_PATHS[:max_paths]]
        seen = set()
        for u in targets:
            if u in seen:
                continue
            seen.add(u)
            try:
                resp = session.get(u, timeout=timeout, allow_redirects=True)
                res = self.analyze(
                    url=u,
                    html=(resp.text or ''),
                    headers=dict(resp.headers),
                    status_code=resp.status_code,
                    redirect_urls=[h.url for h in resp.history],
                    response_cookies=list(resp.cookies),
                )
                combined.merge(res)
            except Exception:
                continue
        return combined


# ---------------------------------------------------------------------------
# Decision engine (Phase 2 / 14)
# ---------------------------------------------------------------------------

@dataclass
class AuthDecision:
    prompt: bool = False
    detected: bool = False
    confidence: int = 0
    accessible: int = 0
    blocked: int = 0
    redirected: int = 0
    unauthorized: int = 0
    unknown: int = 0
    total: int = 0
    protected: int = 0
    public_coverage: int = 0
    estimated_auth_coverage: int = 0
    improvement: int = 0
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'prompt': self.prompt,
            'detected': self.detected,
            'confidence': self.confidence,
            'accessible': self.accessible,
            'blocked': self.blocked,
            'redirected': self.redirected,
            'unauthorized': self.unauthorized,
            'unknown': self.unknown,
            'total': self.total,
            'protected': self.protected,
            'public_coverage': self.public_coverage,
            'estimated_auth_coverage': self.estimated_auth_coverage,
            'improvement': self.improvement,
            'reasons': self.reasons[:8],
        }

    def coverage_message(self) -> str:
        if not self.detected:
            return "No authentication detected; public coverage reflects the full scan."
        return (
            f"Using authentication is estimated to increase coverage "
            f"from {self.public_coverage}% to approximately {self.estimated_auth_coverage}%."
        )


class AuthDecisionEngine:
    """Measure public/protected coverage and decide when a prompt is useful."""

    def __init__(self, min_confidence: int = 50, min_improvement: int = 10,
                 auth_recovery_factor: float = 0.85):
        self.min_confidence = min_confidence
        self.min_improvement = min_improvement
        self.auth_recovery_factor = auth_recovery_factor

    def analyze(self, detection: AuthDetectionResult,
                classifications: Optional[List[Dict[str, Any]]] = None) -> AuthDecision:
        classifications = classifications or []
        counts = {'accessible': 0, 'blocked': 0, 'redirected': 0,
                  'unauthorized': 0, 'unknown': 0}
        for c in classifications:
            key = (c or {}).get('classification', 'unknown')
            counts[key] = counts.get(key, 0) + 1

        total = sum(counts.values())
        accessible = counts['accessible']
        blocked = counts['blocked']
        redirected = counts['redirected']
        unauthorized = counts['unauthorized']
        unknown = counts['unknown']
        protected = blocked + redirected + unauthorized

        public_coverage = int((accessible / total) * 100) if total else 100
        if total == 0:
            public_coverage = 100 if not detection.detected else 0

        estimated_auth_coverage = int(min(
            100, public_coverage + protected * self.auth_recovery_factor * 100 / max(1, total)
        ))
        improvement = max(0, estimated_auth_coverage - public_coverage)

        prompt = (
            detection.detected
            and detection.confidence >= self.min_confidence
            and protected > 0
            and improvement >= self.min_improvement
        )

        reasons = list(detection.reasons[:5])
        if protected > 0:
            reasons.append(
                f"{protected} protected resource(s) detected "
                f"({blocked} blocked, {redirected} redirected, {unauthorized} unauthorized)"
            )

        return AuthDecision(
            prompt=prompt,
            detected=detection.detected,
            confidence=detection.confidence,
            accessible=accessible,
            blocked=blocked,
            redirected=redirected,
            unauthorized=unauthorized,
            unknown=unknown,
            total=total,
            protected=protected,
            public_coverage=public_coverage,
            estimated_auth_coverage=estimated_auth_coverage,
            improvement=improvement,
            reasons=reasons,
        )


# ---------------------------------------------------------------------------
# Session management (Phases 4 / 5 / 8)
# ---------------------------------------------------------------------------

@dataclass
class AuthSession:
    method: str = "public"
    state: AuthState = AuthState.PUBLIC_ONLY
    cookies: Dict[str, str] = field(default_factory=dict)
    cookie_domain: str = ""
    token: str = ""
    token_type: str = "Bearer"
    message: str = ""
    extra_headers: Dict[str, str] = field(default_factory=dict)
    login_url: str = ""
    username: str = ""
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)

    # -- mutators ----------------------------------------------------------
    def set_cookie(self, name: str, value: str, domain: str = "") -> None:
        name = str(name).strip()
        if not name:
            return
        self.cookies[name] = str(value)
        if domain:
            self.cookie_domain = domain
        if self.method == "public":
            self.method = "cookies"
        self.state = AuthState.AUTHENTICATED
        self.last_updated = time.time()

    def set_cookies_from_string(self, cookie_str: str, domain: str = "") -> None:
        for part in (cookie_str or '').split(';'):
            part = part.strip()
            if not part or '=' not in part:
                continue
            name, _, value = part.partition('=')
            self.set_cookie(name, value, domain)

    def set_bearer_token(self, token: str, token_type: str = "Bearer") -> None:
        token = (token or '').strip()
        if not token:
            return
        self.token = token
        self.token_type = token_type or "Bearer"
        self.method = "bearer"
        self.state = AuthState.AUTHENTICATED
        self.last_updated = time.time()

    def set_jwt_token(self, token: str) -> None:
        """Attach a JWT as an Authorization bearer token (method = 'jwt')."""
        token = (token or '').strip()
        if not token:
            return
        self.token = token
        self.token_type = "Bearer"
        self.method = "jwt"
        self.state = AuthState.AUTHENTICATED
        self.last_updated = time.time()

    def set_headers(self, headers: Dict[str, str]) -> None:
        for k, v in (headers or {}).items():
            self.extra_headers[k] = str(v)

    def configure_headers(self, headers: Dict[str, str]) -> None:
        """Custom HTTP header authentication (method = 'headers')."""
        clean = {str(k).strip(): str(v).strip() for k, v in (headers or {}).items()
                 if str(k).strip() and str(v).strip()}
        if not clean:
            return
        self.extra_headers.update(clean)
        self.method = "headers"
        self.state = AuthState.AUTHENTICATED
        self.last_updated = time.time()

    # -- transport ----------------------------------------------------------
    def apply_to(self, session) -> None:
        """Attach cookies and Authorization header to a requests session."""
        if session is None:
            return
        if self.cookies:
            try:
                for name, value in self.cookies.items():
                    if self.cookie_domain:
                        session.cookies.set(name, value, domain=self.cookie_domain)
                    else:
                        session.cookies.set(name, value)
            except Exception:
                pass
        if self.token:
            try:
                session.headers['Authorization'] = f"{self.token_type} {self.token}"
            except Exception:
                pass
        for k, v in self.extra_headers.items():
            try:
                session.headers[k] = v
            except Exception:
                pass

    def update_from_response(self, response) -> bool:
        """Refresh in-memory cookies from Set-Cookie headers (Phase 8)."""
        if response is None:
            return False
        try:
            set_cookies = response.headers.get_list('Set-Cookie')
        except Exception:
            set_cookies = response.headers.get('Set-Cookie')
        if not set_cookies:
            return False
        if isinstance(set_cookies, str):
            set_cookies = [set_cookies]
        changed = False
        for sc in set_cookies:
            name, _, rest = sc.partition('=')
            name = name.strip()
            if not name:
                continue
            lower = sc.lower()
            if 'max-age=0' in lower or 'expires=thu, 01 jan 1970' in lower or \
               'expires=0' in lower:
                if name in self.cookies:
                    del self.cookies[name]
                    changed = True
                continue
            value = rest.split(';')[0].strip()
            self.cookies[name] = value
            changed = True
        if changed:
            self.state = AuthState.AUTHENTICATED
            self.last_updated = time.time()
        return changed

    # -- state -------------------------------------------------------------
    def mark_expired(self) -> None:
        self.state = AuthState.SESSION_EXPIRED

    def mark_login_failed(self, message: str = "") -> None:
        self.state = AuthState.LOGIN_FAILED
        self.message = redact_text(message or "Login failed")

    def mark_token_invalid(self, message: str = "") -> None:
        self.state = AuthState.TOKEN_INVALID
        self.message = redact_text(message or "Token rejected")

    def is_authenticated(self) -> bool:
        return self.state == AuthState.AUTHENTICATED

    def clear(self) -> None:
        self.cookies.clear()
        self.token = ""
        self.extra_headers = {}
        self.method = "public"
        self.state = AuthState.PUBLIC_ONLY

    # -- export ------------------------------------------------------------
    def to_dict(self, redact: bool = True) -> Dict[str, Any]:
        data = {
            'method': self.method,
            'method_label': AUTH_METHOD_LABELS.get(self.method, self.method),
            'state': self.state.value,
            'state_label': AUTH_STATE_LABELS.get(self.state, self.state.value),
            'cookie_names': sorted(self.cookies.keys()),
            'cookie_domain': self.cookie_domain,
            'token_type': self.token_type,
            'has_token': bool(self.token),
            'login_url': self.login_url,
            'username': (self.username[:3] + '***') if self.username else '',
            'message': redact_text(self.message) if redact else self.message,
            'is_authenticated': self.is_authenticated(),
        }
        if not redact:
            data['cookies'] = dict(self.cookies)
            data['token'] = self.token
            data['username'] = self.username
        return data


# ---------------------------------------------------------------------------
# Login profiles (Phase 6)
# ---------------------------------------------------------------------------

@dataclass
class LoginProfile:
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: str = ""
    csrf_token: str = ""
    submit_method: str = "post"  # 'post' | 'json' | 'multipart' | 'form'
    additional_headers: Dict[str, str] = field(default_factory=dict)
    hidden_fields: Dict[str, str] = field(default_factory=dict)
    success_indicators: List[str] = field(default_factory=lambda: [
        'dashboard', 'logout', 'sign out', 'welcome', 'profile', 'admin', 'account',
    ])
    failure_indicators: List[str] = field(default_factory=lambda: [
        'invalid', 'incorrect', 'wrong password', 'login failed',
        'authentication failed', 'unauthorized', 'sign in', 'credentials',
    ])

    def build_request(self) -> Dict[str, Any]:
        data = dict(self.hidden_fields or {})
        data[self.username_field] = self.username
        data[self.password_field] = self.password
        if self.csrf_field and self.csrf_token:
            data[self.csrf_field] = self.csrf_token
        headers = dict(self.additional_headers or {})
        request: Dict[str, Any] = {'url': self.login_url, 'method': 'POST', 'headers': headers}
        if self.submit_method == 'json':
            request['json'] = data
            headers.setdefault('Content-Type', 'application/json')
        elif self.submit_method == 'multipart':
            request['files'] = {k: (None, str(v)) for k, v in data.items()}
        else:  # form urlencoded
            request['data'] = data
            headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        return request

    def to_dict(self, redact: bool = True) -> Dict[str, Any]:
        data = {
            'login_url': self.login_url,
            'username_field': self.username_field,
            'password_field': self.password_field,
            'csrf_field': self.csrf_field,
            'submit_method': self.submit_method,
            'hidden_fields': list(self.hidden_fields.keys()),
            'username': (self.username[:3] + '***') if self.username else '',
        }
        if not redact:
            data['username'] = self.username
            data['password'] = self.password
            data['csrf_token'] = self.csrf_token
            data['hidden_fields'] = self.hidden_fields
        return data


class LoginAuthenticator:
    """Perform a real login using a LoginProfile and capture the resulting session."""

    def __init__(self, session=None, timeout: int = 15):
        self.session = session
        self.timeout = timeout

    def authenticate(self, profile: LoginProfile) -> Tuple[AuthSession, Any]:
        import requests
        auth = AuthSession(method='login', state=AuthState.AUTH_REQUIRED)
        auth.login_url = profile.login_url
        auth.username = profile.username

        session = self.session or requests.Session()
        try:
            resp = session.get(profile.login_url, timeout=self.timeout, allow_redirects=True)
            if getattr(resp, 'text', ''):
                if profile.csrf_field and not profile.csrf_token:
                    token = self._extract_csrf(resp.text, profile.csrf_field)
                    if token:
                        profile.csrf_token = token
                for k, v in self._extract_hidden_fields(resp.text).items():
                    if (k not in profile.hidden_fields
                            and k not in (profile.username_field, profile.password_field)):
                        profile.hidden_fields[k] = v
        except Exception:
            pass

        req = profile.build_request()
        try:
            resp = session.request(
                req['method'], req['url'], timeout=self.timeout,
                headers=req['headers'], data=req.get('data'),
                json=req.get('json'), files=req.get('files'),
                allow_redirects=True,
            )
        except Exception as exc:
            auth.mark_login_failed(f"Login request failed: {str(exc)[:200]}")
            return auth, None

        if self._evaluate(resp, profile):
            auth.state = AuthState.AUTHENTICATED
            auth.message = "Login succeeded"
            for c in session.cookies:
                auth.set_cookie(c.name, c.value, domain=getattr(c, 'domain', '') or '')
            return auth, resp

        auth.mark_login_failed("Credentials rejected or login form returned")
        return auth, resp

    def _evaluate(self, resp, profile: LoginProfile) -> bool:
        text = (getattr(resp, 'text', '') or '').lower()
        final_url = (getattr(resp, 'url', '') or '').lower()
        if any(i in text for i in profile.failure_indicators):
            return False
        if any(i in text for i in profile.success_indicators):
            return True
        if getattr(resp, 'status_code', 0) in (301, 302, 303, 307, 308):
            return True
        if is_login_path(final_url) and not text:
            return False
        return False

    @staticmethod
    def _extract_csrf(html: str, field_name: str) -> str:
        escaped = re.escape(field_name)
        m = re.search(r'name=["\']' + escaped + r'["\'][^>]*value=["\']([^"\']+)["\']', html, re.I)
        if not m:
            m = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']' + escaped + r'["\']', html, re.I)
        if not m and 'csrf' in field_name.lower():
            m = re.search(r'value=["\']([A-Za-z0-9\-_.]{12,})["\']', html)
        return m.group(1) if m else ""

    @staticmethod
    def _extract_hidden_fields(html: str) -> Dict[str, str]:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            return {
                i.get('name'): i.get('value', '')
                for i in soup.find_all('input', {'type': 'hidden'})
                if i.get('name')
            }
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# Browser session import (Phase 7)
# ---------------------------------------------------------------------------

class SessionImporter:
    """Import cookies from installed browsers for a single domain (in-memory only)."""

    SUPPORTED_BROWSERS = ('chrome', 'edge', 'firefox', 'brave')

    def __init__(self, approval: bool = True):
        self.approval = approval
        self.imported_from = ""

    def import_for_domain(self, domain: str, browser: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
        """Return cookies for a domain, or None when unavailable."""
        if not self.approval:
            raise PermissionError("Browser session import requires explicit user approval")
        domain = str(domain or '').replace('https://', '').replace('http://', '').strip('/').lower()
        if not domain:
            return None
        browsers = [browser] if browser else list(self.SUPPORTED_BROWSERS)
        for b in browsers:
            db_path = self._find_db(b)
            if not db_path or not os.path.exists(db_path):
                continue
            cookies = self._read_cookies(db_path, domain, b)
            if cookies:
                self.imported_from = f"{b}:{os.path.basename(os.path.dirname(db_path))}"
                return cookies
        return None

    def _find_db(self, browser: str) -> str:
        home = os.path.expanduser('~')
        if browser == 'firefox':
            base = (os.path.join(os.environ.get('APPDATA', ''), 'Mozilla', 'Firefox', 'Profiles')
                    if os.name == 'nt'
                    else os.path.join(home, '.mozilla', 'firefox'))
            for root, _dirs, files in os.walk(base):
                if 'cookies.sqlite' in files:
                    return os.path.join(root, 'cookies.sqlite')
            return ''
        vendors = {
            'chrome': ('Google', 'Chrome'),
            'edge': ('Microsoft', 'Edge'),
            'brave': ('BraveSoftware', 'Brave-Browser'),
        }
        if browser not in vendors:
            return ''
        vendor, product = vendors[browser]
        if os.name == 'nt':
            base = os.path.join(os.environ.get('LOCALAPPDATA', ''), vendor, product, 'User Data')
        elif os.name == 'darwin':
            base = os.path.join(home, 'Library', 'Application Support', product)
        else:
            base = os.path.join(home, '.config', product)
        for profile in ('Default', 'Profile 1'):
            db = os.path.join(base, profile, 'Network', 'Cookies')
            if not os.path.exists(db):
                db = os.path.join(base, profile, 'Cookies')
            if os.path.exists(db):
                return db
        return ''

    def _read_cookies(self, db_path: str, domain: str, browser: str) -> List[Dict[str, Any]]:
        cookies: List[Dict[str, Any]] = []
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(cookies)")
            columns = [row[1] for row in cur.fetchall()]
            select = "SELECT * FROM cookies"
            cur.execute(select)
            rows = cur.fetchall()
            conn.close()
        except Exception:
            return []
        for row in rows:
            cookie = self._row_to_cookie(row, columns, browser)
            if not cookie:
                continue
            if self._domain_match(cookie.get('domain', ''), domain):
                cookies.append(cookie)
        return cookies

    @staticmethod
    def _domain_match(cookie_domain: str, target_domain: str) -> bool:
        cd = str(cookie_domain or '').lstrip('.').lower()
        td = str(target_domain or '').lstrip('.').lower()
        if not cd or not td:
            return False
        return cd == td or td.endswith('.' + cd)

    def _row_to_cookie(self, row: Tuple, columns: List[str], browser: str) -> Optional[Dict[str, Any]]:
        data = dict(zip(columns, row))
        if browser == 'firefox':
            name = self._to_str(data.get('name'))
            value = self._to_str(data.get('value'))
            domain = self._to_str(data.get('host'))
            if not name or not domain:
                return None
            return {'name': name, 'value': value, 'domain': domain,
                    'path': self._to_str(data.get('path')) or '/', 'secure': bool(data.get('isSecure'))}
        # chromium family
        name = self._to_str(data.get('name'))
        domain = self._to_str(data.get('host_key'))
        if not name or not domain:
            return None
        value = self._to_str(data.get('value'))
        encrypted = bytes(data.get('encrypted_value') or b'')
        if not value and encrypted:
            decrypted = self._decrypt_chromium_value(encrypted)
            value = decrypted if decrypted else ''
        return {'name': name, 'value': value, 'domain': domain,
                'path': self._to_str(data.get('path')) or '/', 'secure': bool(data.get('is_secure'))}

    @staticmethod
    def _to_str(v: Any) -> str:
        if isinstance(v, bytes):
            return v.decode('utf-8', errors='replace')
        return str(v or '')

    def _decrypt_chromium_value(self, encrypted: bytes) -> str:
        """Best-effort Chrome v10 (AES-GCM + DPAPI) decryption; returns '' on failure."""
        if len(encrypted) < 15:
            return ''
        try:
            import base64
            import json
            local_state = self._local_state_path()
            if not local_state or not os.path.exists(local_state):
                return ''
            with open(local_state, 'r', encoding='utf-8') as f:
                key = json.load(f)['os_crypt']['encrypted_key']
            key = base64.b64decode(key)
            if not key.startswith(b'DPAPI'):
                return ''
            key = key[5:]
            try:
                import win32crypt
                key = win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
            except Exception:
                return ''
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce, ciphertext = encrypted[3:15], encrypted[15:]
            return AESGCM(key).decrypt(nonce, ciphertext, None).decode('utf-8', errors='replace')
        except Exception:
            return ''

    def _local_state_path(self) -> str:
        if os.name != 'nt':
            return ''
        return os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome',
                            'User Data', 'Local State')


# ---------------------------------------------------------------------------
# Extension points (Phase 15) - interfaces only
# ---------------------------------------------------------------------------

class AuthProvider:
    """Base interface for future authentication providers (SSO, MFA, API...)."""
    name = "base"

    def authenticate(self, session: Optional['AuthSession'] = None) -> AuthSession:
        raise NotImplementedError


class SsoProvider(AuthProvider):
    """Future: SSO providers (OIDC / SAML / Azure AD / Okta...)."""
    name = "sso"

    def authenticate(self, session=None) -> AuthSession:
        raise NotImplementedError("SSO provider integration is planned")


class MfaWorkflow(AuthProvider):
    """Future: MFA-aware user-assisted workflows."""
    name = "mfa"

    def authenticate(self, session=None) -> AuthSession:
        raise NotImplementedError("MFA-aware workflows are planned")


class ApiAuthProvider(AuthProvider):
    """Future: API authentication providers (API keys, OAuth2 client credentials...)."""
    name = "api"

    def authenticate(self, session=None) -> AuthSession:
        raise NotImplementedError("API authentication providers are planned")


class BrowserAutomationPlugin(AuthProvider):
    """Future: browser automation (Playwright) login extraction for SPAs."""
    name = "browser_automation"

    def authenticate(self, session=None) -> AuthSession:
        raise NotImplementedError("Browser automation login is planned (Phase 12)")
