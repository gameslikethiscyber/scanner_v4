import re
import logging
from urllib.parse import urljoin
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.CSRF')


class CSRFScanner(BaseScanner):
    """
    CSRF Protection scanner — v2.

    The old version only checked whether the word "csrf" (or similar)
    appeared anywhere in the page HTML via regex. That produces both:
      - false PASS: a field named csrf_token exists but the server never
        actually validates it
      - false FAIL/WARNING: protection exists (e.g. SameSite cookies)
        without a classic token field

    This version:
      1. Extracts real <form method="post"> blocks from the page.
      2. Detects a hidden anti-CSRF token field by name pattern.
      3. If found, submits the form once normally and once with the
         token field removed, and compares the two responses. If the
         server behaves identically either way, the token is decorative
         and not actually enforced -> real finding.
      4. Falls back to SameSite cookie inspection when there are no
         POST forms to test.
    """

    TOKEN_NAME_PATTERNS = [
        r'csrf', r'_token', r'csrf_token', r'csrfmiddlewaretoken',
        r'__RequestVerificationToken', r'csrf-param', r'CSRFName',
        r'csrf_test_name', r'YII_CSRF_TOKEN', r'CRAFT_CSRF_TOKEN',
        r'authenticity_token', r'nonce',
    ]

    FORM_RE = re.compile(r'<form\b[^>]*>.*?</form>', re.IGNORECASE | re.DOTALL)
    FORM_OPEN_RE = re.compile(r'<form\b([^>]*)>', re.IGNORECASE)
    INPUT_TAG_RE = re.compile(r'<input\b[^>]*>', re.IGNORECASE)

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "CSRF Protection"

    # ---------------------------------------------------------------
    # Parsing helpers
    # ---------------------------------------------------------------

    @staticmethod
    def _attr(tag_or_attrs, name):
        m = re.search(name + r'\s*=\s*["\']([^"\']*)["\']', tag_or_attrs, re.IGNORECASE)
        return m.group(1) if m else None

    def _extract_forms(self, html):
        forms = []
        for form_match in self.FORM_RE.finditer(html):
            form_html = form_match.group(0)
            open_tag_match = self.FORM_OPEN_RE.search(form_html)
            attrs = open_tag_match.group(1) if open_tag_match else ''
            method = (self._attr(attrs, 'method') or 'get').lower()
            action_raw = self._attr(attrs, 'action') or ''
            action = urljoin(self.target, action_raw) if action_raw else self.target

            hidden_fields = {}
            field_names = []
            for input_tag in self.INPUT_TAG_RE.findall(form_html):
                name = self._attr(input_tag, 'name')
                if not name:
                    continue
                field_names.append(name)
                itype = (self._attr(input_tag, 'type') or 'text').lower()
                if itype == 'hidden':
                    hidden_fields[name] = self._attr(input_tag, 'value') or ''

            token_field = None
            for name in hidden_fields:
                if any(re.search(p, name, re.IGNORECASE) for p in self.TOKEN_NAME_PATTERNS):
                    token_field = name
                    break

            forms.append({
                'method': method,
                'action': action,
                'hidden_fields': hidden_fields,
                'token_field': token_field,
                'field_names': field_names,
            })
        return forms

    def _submit(self, action, method, data):
        try:
            if method == 'post':
                return self.session.post(action, data=data, timeout=10, allow_redirects=False)
            return self.session.get(action, params=data, timeout=10, allow_redirects=False)
        except Exception:
            return None

    @staticmethod
    def _responses_equivalent(r1, r2):
        if r1 is None or r2 is None:
            return None
        if r1.status_code != r2.status_code:
            return False
        len1, len2 = len(r1.text), len(r2.text)
        if len1 == 0 and len2 == 0:
            return True
        diff = abs(len1 - len2) / max(len1, len2, 1)
        return diff < 0.05

    def _has_samesite_cookie(self):
        try:
            for cookie in self.session.cookies:
                rest = getattr(cookie, '_rest', {}) or {}
                samesite = rest.get('SameSite') or rest.get('samesite') or ''
                if str(samesite).lower() in ('strict', 'lax'):
                    return True
        except Exception:
            pass
        return False

    # ---------------------------------------------------------------
    # Main scan
    # ---------------------------------------------------------------

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            resp = self.session.get(self.target, timeout=10)
            forms = self._extract_forms(resp.text)
            post_forms = [f for f in forms if f['method'] == 'post']

            finding.tests_performed = max(len(post_forms), 1)
            finding.tests_run = finding.tests_performed

            if not post_forms:
                if self._has_samesite_cookie():
                    finding.add_evidence(
                        self._evidence_builder.likely(
                            "No POST forms found on this page; session cookies use SameSite protection",
                            payload=None,
                        )
                    )
                else:
                    finding.add_evidence(
                        self._evidence_builder.possible(
                            "No POST forms found on this page to evaluate CSRF protection",
                            payload=None,
                        )
                    )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
                return finding

            unprotected_forms = []
            unenforced_forms = []

            for form in post_forms:
                if not form['token_field']:
                    unprotected_forms.append(form)
                    continue

                token_name = form['token_field']

                baseline_data = dict(form['hidden_fields'])
                for name in form['field_names']:
                    if name not in baseline_data:
                        baseline_data[name] = 'test'

                tampered_data = dict(baseline_data)
                del tampered_data[token_name]

                baseline_resp = self._submit(form['action'], 'post', baseline_data)
                tampered_resp = self._submit(form['action'], 'post', tampered_data)

                equivalent = self._responses_equivalent(baseline_resp, tampered_resp)

                if equivalent is True:
                    unenforced_forms.append(form)

            if unprotected_forms:
                for form in unprotected_forms[:3]:
                    self.capture_http_evidence(
                        finding,
                        f"POST form to '{form['action']}' has no CSRF token field",
                        resp=None, payload=form['action'], method='POST',
                    )
                finding.status = Status.FAIL
                finding.severity = Severity.MEDIUM
                finding.tests_passed = finding.tests_performed - len(unprotected_forms)
                finding.add_recommendation(
                    1, "Add CSRF tokens to all state-changing forms",
                    "These forms accept POST requests with no anti-CSRF token, allowing forged cross-site requests.",
                    "Add a per-session anti-CSRF token (synchronizer token pattern) to every form.",
                    ["OWASP: CSRF Prevention Cheat Sheet"],
                )

            if unenforced_forms:
                for form in unenforced_forms[:3]:
                    self.capture_http_evidence(
                        finding,
                        f"Form to '{form['action']}' has a CSRF token field ('{form['token_field']}') "
                        f"but the server accepted the request with the token removed — token is not validated",
                        resp=None, payload=form['action'], method='POST',
                    )
                finding.status = Status.FAIL
                finding.severity = Severity.HIGH
                finding.confirmations += len(unenforced_forms)
                finding.cross_validated = True
                finding.add_recommendation(
                    1, "Enforce CSRF token validation server-side",
                    "A CSRF token field is present in the HTML but the server accepts requests even when "
                    "it is missing, meaning the token is decorative and provides no real protection.",
                    "Validate the CSRF token on every state-changing request and reject/redirect when "
                    "absent or invalid.",
                    ["OWASP: CSRF Prevention Cheat Sheet"],
                )

            if not unprotected_forms and not unenforced_forms:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"All {len(post_forms)} POST form(s) carry a CSRF token that the server actually validates",
                        payload=None,
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error scanning CSRF: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
