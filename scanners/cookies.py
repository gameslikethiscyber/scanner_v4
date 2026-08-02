import datetime
import logging
from collections import defaultdict
from urllib.parse import urlparse

from core.finding import Finding
from scanners.base import BaseScanner
from core.response_analyzer import ResponseAnalyzer, CookieAnalysis

logger = logging.getLogger('SeaScanner.Cookies')

SESSION_FRAGMENTS = (
    'sid', 'session', 'auth', 'token', 'csrf', 'jwt', 'login', 'account',
    'remember', 'connect', 'phpsessid', 'jsessionid', 'asp', 'laravel',
    'django', 'wordpress', 'wp_', 'user', 'profile',
)

PERSISTENCE_WINDOW_DAYS = 7
CONF_WEIGHTS = {'critical': 30, 'high': 18, 'medium': 8, 'low': 3}


class CookiesScanner(BaseScanner):

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Cookies Security"

    # ---------------------------------------------------------------
    # Classification helpers
    # ---------------------------------------------------------------

    @staticmethod
    def _is_session_like(name: str, prefix: str) -> bool:
        if prefix:
            return True
        low = (name or '').lower()
        return any(frag in low for frag in SESSION_FRAGMENTS)

    @staticmethod
    def _is_persistent_expiry(expires) -> bool:
        if not expires:
            return False
        try:
            ts = float(expires)
        except (TypeError, ValueError):
            return False
        try:
            expiry = datetime.datetime.fromtimestamp(ts,
                                                     tz=datetime.timezone.utc)
        except (ValueError, OverflowError, OSError):
            return False
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        return (expiry - now).total_seconds() > PERSISTENCE_WINDOW_DAYS * 86400

    @staticmethod
    def _is_broad_domain(domain: str) -> bool:
        if not domain:
            return False
        labels = domain.strip('.').split('.')
        if len(labels) <= 1:
            return True
        return False

    @staticmethod
    def _confidence(issues: list, count: int) -> int:
        if not issues:
            return 0
        score = sum(CONF_WEIGHTS.get(i['severity'], 3) for i in issues)
        score = score * (1.0 + 0.1 * min(max(count - 1, 0), 3))
        return max(0, min(100, int(score)))

    # ---------------------------------------------------------------
    # Issue derivation
    # ---------------------------------------------------------------

    def _detect(self, ca: CookieAnalysis, target_host: str):
        """Return a list of ``(types, severity, recommendation)`` issues for a
        cookie the jar accepted and normalized.
        """
        issues = []
        sensitive = ca.prefix != ''
        sessionlike = self._is_session_like(ca.name, ca.prefix)

        if not ca.secure:
            if sensitive:
                issues.append(('missing_secure', 'critical',
                               f"Cookie '{ca.name}' uses a hardened prefix "
                               "(__Host-/__Secure-) but the Secure flag is "
                               "missing, defeating the prefix guarantee"))
            elif sessionlike:
                issues.append(('missing_secure', 'high',
                               f"Session cookie '{ca.name}' lacks the Secure "
                               "flag and is transmitted in cleartext"))

        if sessionlike and not ca.httponly:
            issues.append(('missing_httponly', 'medium',
                           f"Session cookie '{ca.name}' is readable by "
                           "JavaScript (no HttpOnly flag), exposing it to XSS"))

        ss = (ca.samesite or '').lower()
        if sessionlike:
            if not ss:
                issues.append(('missing_samesite', 'medium',
                               f"Session cookie '{ca.name}' has no SameSite "
                               "attribute and is sent with cross-site "
                               "requests"))
            elif ss == 'none':
                issues.append(('samesite_none', 'medium',
                               f"Session cookie '{ca.name}' sets SameSite=None, "
                               "permitting cross-site introspection"))

        dom = ''
        if ca.domain and ca.domain.lower() != target_host:
            dom = ca.domain

        if dom or self._is_broad_domain(dom):
            issues.append(('broad_domain', 'high',
                           f"Cookie '{ca.name}' sets Domain={dom} (a broad / "
                           "top-level scope, applicable to unrelated hosts)"))

        if sessionlike and self._is_persistent_expiry(ca.expires):
            issues.append(('persistent_session', 'medium',
                           f"Session cookie '{ca.name}' has a far-future "
                           f"expiry ({ca.expires}) and survives beyond the "
                           "browser session"))

        if sessionlike and not ca.path:
            issues.append(('missing_path', 'low',
                           f"Session cookie '{ca.name}' has no Path attribute "
                           "and is sent site-wide"))

        return issues

    def _raw_cookies(self, resp) -> dict:
        """Parse raw ``Set-Cookie`` headers into ``{name: lowercase attrs}``.

        The requests cookiejar drops cookies whose attributes it considers
        invalid (e.g. a `Domain` at a public suffix such as ``Domain=com``).
        We parse the raw header value so those aren't silently missed.
        """
        raw = []
        try:
            raw = resp.raw.headers.getlist('Set-Cookie') or []
        except Exception:
            one = resp.headers.get('Set-Cookie')
            raw = [one] if one else []
        cookies = {}
        for value in raw:
            segs = [s.strip() for s in value.split(';')]
            if not segs or '=' not in segs[0]:
                continue
            name = segs[0].split('=', 1)[0].strip()
            attrs = {}
            for seg in segs[1:]:
                if not seg:
                    continue
                if '=' in seg:
                    k, _, v = seg.partition('=')
                    attrs[k.strip().lower()] = v.strip()
                else:
                    attrs[seg.lower()] = ''
            cookies.setdefault(name, attrs)
        return cookies

    def _raw_broad_issue(self, name: str, attrs: dict):
        """Broad/prefix domain signals recoverable only from the raw header."""
        dom = attrs.get('domain', '')
        if dom and self._is_broad_domain(dom):
            return ('broad_domain', 'high',
                    f"Cookie '{name}' sets Domain={dom} in its raw Set-Cookie "
                    "header (a broad / top-level scope)")
        if name.startswith('__Host-') and dom:
            return ('prefix_misuse', 'high',
                    f"Cookie '{name}' is __Host- prefixed but sets "
                    f"Domain={dom} (illegal)")
        return None

    # ---------------------------------------------------------------
    # Scan
    # ---------------------------------------------------------------

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            resp = self.session.get(self.target, timeout=10, allow_redirects=True)
            analysis = ResponseAnalyzer.analyze_response(resp)
            cookies = analysis.cookies
            raw_cookies = self._raw_cookies(resp)
            target_host = (urlparse(self.target).hostname or '').lower()

            if not cookies and not raw_cookies:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No cookies found to analyze",
                        payload=None,
                    )
                )
                finding.tests_performed = 0
                finding.tests_run = 0
                finding.tests_passed = 0
                finding.fingerprint['cookie_issues'] = []
                finding.fingerprint['cookie_confidence'] = 0
                return finding

            finding.tests_performed = len(cookies)
            finding.tests_run = len(cookies)

            merged = defaultdict(list)   # name -> list of (type, sev, rec)
            jar_names = set()
            for ca in cookies:
                jar_names.add(ca.name)
                merged[ca.name] = self._detect(ca, target_host)
            for name, attrs in raw_cookies.items():
                broad = self._raw_broad_issue(name, attrs)
                if broad:
                    types = {t for t, _, _ in merged[name]}
                    if broad[0] not in types:
                        merged[name].append(broad)

            cookie_issues = []
            cookies_with_issues = set()
            cookie_evidences = []

            for name in merged:
                issues = merged[name]
                if not issues:
                    continue
                cookies_with_issues.add(name)
                for issue, severity, rec in issues:
                    cookie_issues.append({
                        'type': issue,
                        'name': name,
                        'severity': severity,
                        'recommendation': rec,
                    })

            for ca in cookies:
                items, _ = self._attribute_evidence(ca, merged[ca.name])
                cookie_evidences.extend(items)
            for name, attrs in raw_cookies.items():
                if name in jar_names:
                    continue
                broad = self._raw_broad_issue(name, attrs)
                if broad:
                    ev = self._evidence_builder.likely(broad[2], payload=name)
                    ev.raw_data['matched_signal'] = broad[0]
                    ev.raw_data['severity'] = broad[1]
                    ev.raw_data['type'] = broad[0]
                    ev.raw_data['reliability'] = 'high'
                    ev.raw_data['reproducible'] = True
                    cookie_evidences.append((True, ev))

            # Issues first so a WARNING finding's lead evidence is an issue
            # (never pruned by the SOP #6 positive-observation rule).
            cookie_evidences.sort(key=lambda item: not item[0])
            for _, ev in cookie_evidences:
                finding.add_evidence(ev)

            finding.tests_passed = len(cookies) - len(cookies_with_issues)
            finding.fingerprint['cookie_issues'] = cookie_issues
            finding.fingerprint['cookie_confidence'] = self._confidence(
                cookie_issues, len(cookies))
            finding.fingerprint['cookies'] = [
                {
                    'name': ca.name,
                    'secure': ca.secure,
                    'httponly': ca.httponly,
                    'samesite': ca.samesite,
                    'prefix': ca.prefix,
                    'domain': ca.domain,
                    'path': ca.path,
                    'expires': ca.expires,
                    'session_like': self._is_session_like(ca.name, ca.prefix),
                }
                for ca in cookies
            ]

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.unknown(
                    f"Error scanning cookies: {str(e)}", payload=None)
            )
            finding.scan_errors += 1

        return finding

    def _attribute_evidence(self, ca, issues):
        """Return ``(items, has_issue)``; one evidence item per signal."""
        items = []
        has_issue = bool(issues)

        for issue, severity, rec in issues:
            ev = self._evidence_builder.likely(rec, payload=ca.name)
            ev.raw_data['matched_signal'] = issue
            ev.raw_data['severity'] = severity
            ev.raw_data['type'] = issue
            ev.raw_data['reliability'] = 'high'
            ev.raw_data['reproducible'] = True
            items.append((True, ev))

        if has_issue:
            return items, has_issue

        attributes = []
        if ca.secure:
            attributes.append((False, self._evidence_builder.verified(
                f"Cookie '{ca.name}' is HTTPS-only")))
        if ca.httponly:
            attributes.append((False, self._evidence_builder.verified(
                f"Cookie '{ca.name}' blocks JavaScript access (HttpOnly)")))
        if ca.samesite:
            attributes.append((False, self._evidence_builder.verified(
                f"Cookie '{ca.name}' restricts cross-site sending "
                f"(SameSite={ca.samesite})")))
        if not attributes:
            attributes.append((False, self._evidence_builder.verified(
                f"Cookie '{ca.name}' is set with no restrictive attributes; "
                "assess whether it carries sensitive data")))
        items.extend(attributes)
        return items, has_issue