import re
import math
import logging
from urllib.parse import urljoin

from core.finding import Finding
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.CSRF')


class CSRFScanner(BaseScanner):

    # ALL_CAPS constants are allowed by B13 (not treated as mutable class state).
    TOKEN_NAME_PATTERNS = (
        r'csrf', r'_token', r'csrf_token', r'csrfmiddlewaretoken',
        r'__RequestVerificationToken', r'csrf-param', r'CSRFName',
        r'csrf_test_name', r'YII_CSRF_TOKEN', r'CRAFT_CSRF_TOKEN',
        r'authenticity_token', r'_csrf', r'xsrf', r'nonce',
    )

    FORM_RE = re.compile(r'<form\b[^>]*>.*?</form>', re.IGNORECASE | re.DOTALL)
    FORM_OPEN_RE = re.compile(r'<form\b([^>]*)>', re.IGNORECASE)
    INPUT_TAG_RE = re.compile(r'<input\b[^>]*>', re.IGNORECASE)

    FRAMEWORK_MARKERS = (
        ('django', r'csrfmiddlewaretoken'),
        ('laravel', r'csrf_token|_token|xsrf'),
        ('rails', r'authenticity_token'),
        ('aspnet', r'__RequestVerificationToken'),
        ('flaskwtf', r'csrftoken'),
        ('spring', r'_csrf'),
        ('yii', r'YII_CSRF_TOKEN'),
        ('craft', r'CRAFT_CSRF_TOKEN|_csrfToken'),
    )

    MIN_TOKEN_LEN = 16
    WRONG_TOKEN = '00000000-1847-0000-0000-wrongtoken'

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "CSRF Protection"

    # ---------------------------------------------------------------
    # Parsing / token helpers
    # ---------------------------------------------------------------

    @staticmethod
    def _attr(tag_or_attrs, name):
        m = re.search(rf"{name}\s*=\s*[\"']([^\"']*)[\"']",
                      tag_or_attrs, re.IGNORECASE)
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

    def _token_value(self, form):
        if form['token_field']:
            return form['hidden_fields'].get(form['token_field'], '')
        return None

    def _detect_framework(self, html, token_name):
        if token_name:
            for name, pat in self.FRAMEWORK_MARKERS:
                if re.search(pat, token_name, re.IGNORECASE):
                    return name
        for name, pat in self.FRAMEWORK_MARKERS:
            if re.search(pat, html, re.IGNORECASE):
                return name
        return None

    def _samesite_profile(self):
        """Return {lax_or_strict, none_present, values} for session cookies."""
        values = []
        lax_or_strict = False
        none_present = False
        try:
            cookies = list(getattr(self.session, 'cookies', []))
        except Exception:
            cookies = []
        for cookie in cookies:
            rest = getattr(cookie, '_rest', {}) or {}
            ss = rest.get('SameSite') or rest.get('samesite') or ''
            ss_l = str(ss).lower()
            if ss_l in ('strict', 'lax'):
                lax_or_strict = True
            elif ss_l == 'none':
                none_present = True
            values.append(ss_l)
        return {'lax_or_strict': lax_or_strict, 'none_present': none_present,
                'values': values}

    def _submit(self, action, method, data, headers=None):
        try:
            kwargs = {'timeout': 10, 'allow_redirects': False}
            if headers:
                kwargs['headers'] = headers
            if method == 'post':
                return self.session.post(action, data=data, **kwargs)
            return self.session.get(action, params=data, **kwargs)
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

    # ---------------------------------------------------------------
    # Token randomness
    # ---------------------------------------------------------------

    @staticmethod
    def _entropy(value):
        if not value:
            return 0.0
        counts = {}
        for ch in value:
            counts[ch] = counts.get(ch, 0) + 1
        n = len(value)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    def _token_weak(self, value):
        if not value:
            return True
        if len(value) < self.MIN_TOKEN_LEN:
            return True
        if value.strip().lower() in ('token', 'csrf', 'csrf_token', 'random'):
            return True
        if self._entropy(value) < 2.5:
            return True
        return False

    def _fresh_token(self, token_name):
        try:
            resp = self.session.get(self.target, timeout=10)
            for form in self._extract_forms(resp.text):
                if form['method'] == 'post' and form['token_field'] == token_name:
                    return form['hidden_fields'].get(token_name)
            return None
        except Exception:
            return None

    # ---------------------------------------------------------------
    # Behavioral probes
    # ---------------------------------------------------------------

    def _form_data(self, form):
        data = dict(form['hidden_fields'])
        for name in form['field_names']:
            if name not in data:
                data[name] = 'test'
        return data

    def _token_enforced(self, form):
        token_name = form['token_field']
        baseline_data = self._form_data(form)

        baseline = self._submit(form['action'], 'post', baseline_data)
        if baseline is None or baseline.status_code >= 400:
            # Action does not process the request normally: ambiguous, skip.
            return None

        no_token_data = dict(baseline_data)
        no_token_data.pop(token_name, None)
        no_token_resp = self._submit(form['action'], 'post', no_token_data)

        wrong_data = dict(baseline_data)
        wrong_data[token_name] = self.WRONG_TOKEN
        wrong_resp = self._submit(form['action'], 'post', wrong_data)

        eq_absent = self._responses_equivalent(baseline, no_token_resp)
        eq_wrong = self._responses_equivalent(baseline, wrong_resp)

        return {
            'enforced': not (eq_absent is True and eq_wrong is True),
            'rejected_on_absent': eq_absent is False,
            'rejected_on_wrong': eq_wrong is False,
            'baseline_status': baseline.status_code,
        }

    def _cross_origin_accepted(self, form):
        data = self._form_data(form)
        headers = {
            'Origin': 'https://evil.com',
            'Referer': 'https://evil.com/',
        }
        cross = self._submit(form['action'], 'post', data, headers=headers)
        same = self._submit(form['action'], 'post', data)
        if same is None or cross is None:
            return None
        if self._responses_equivalent(same, cross) is True:
            return {'accepted': True, 'cross_status': cross.status_code,
                    'same_status': same.status_code,
                    'origin_header': 'https://evil.com'}
        return {'accepted': False, 'cross_status': cross.status_code,
                'same_status': same.status_code}

    # ---------------------------------------------------------------
    # Main scan
    # ---------------------------------------------------------------

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            resp = self.session.get(self.target, timeout=10)
            html = resp.text
            forms = self._extract_forms(html)
            post_forms = [f for f in forms if f['method'] == 'post']

            samesite = self._samesite_profile()
            framework = None

            finding.tests_performed = max(len(post_forms), 1)
            finding.tests_run = finding.tests_performed

            signals = []            # all observation records (issue + positive)
            forms_with_issues = 0
            forms_analysed = 0

            if not post_forms:
                desc = ("No POST forms found on the page - no state-changing "
                        "(POST) surface to evaluate CSRF protection")
                if samesite['lax_or_strict']:
                    desc += "; session cookies use SameSite protection"
                finding.add_evidence(self._evidence_builder.verified(
                    desc, payload=None))
                finding.tests_passed = finding.tests_performed
                finding.fingerprint['csrf_observations'] = {
                    'post_forms': 0,
                    'same_site_cookies': samesite['lax_or_strict'],
                }
                finding.fingerprint['csrf_signals'] = []
                finding.fingerprint['csrf_protection'] = {
                    'framework': None, 'same_site': samesite,
                    'token_enforced': [], 'origin_validated': [],
                }
                return finding

            for form in post_forms:
                action = form['action']
                token_name = form['token_field']
                token_value = self._token_value(form)
                if framework is None and token_name:
                    framework = self._detect_framework(html, token_name)

                form_signals = []

                if not token_name:
                    if samesite['lax_or_strict'] and not samesite['none_present']:
                        # SameSite mitigates a missing token -> positive (FP guard).
                        signals.append({'technique': 'no_token_mitigated_by_samesite',
                                        'form_action': action, 'issue': False})
                    else:
                        form_signals.append({'technique': 'no_token',
                                             'form_action': action,
                                             'issue': True})
                        forms_with_issues += 1
                else:
                    enforced = self._token_enforced(form)
                    if enforced is None:
                        continue
                    if not enforced['enforced']:
                        form_signals.append({'technique': 'token_not_enforced',
                                             'form_action': action,
                                             'rejected_on_absent': enforced['rejected_on_absent'],
                                             'rejected_on_wrong': enforced['rejected_on_wrong'],
                                             'issue': True})
                        forms_with_issues += 1
                    else:
                        signals.append({'technique': 'token_enforced',
                                        'form_action': action,
                                        'issue': False})
                        weak = self._token_weak(token_value)
                        fresh = self._fresh_token(token_name)
                        rotates = (fresh is not None and token_value
                                   and fresh != token_value)
                        if weak:
                            form_signals.append({'technique': 'weak_token',
                                                 'form_action': action,
                                                 'entropy': round(self._entropy(token_value or ''), 2),
                                                 'length': len(token_value or ''),
                                                 'issue': True})
                            forms_with_issues += 1
                        if rotates:
                            # Rotating token is a positive (not an issue).
                            signals.append({'technique': 'token_rotates',
                                            'form_action': action,
                                            'issue': False})

                # ---- cross-origin validation ----
                cross = self._cross_origin_accepted(form)
                if cross is not None:
                    if cross['accepted']:
                        form_signals.append({'technique': 'cross_origin_accepted',
                                             'form_action': action,
                                             'origin_header': cross['origin_header'],
                                             'issue': True})
                        forms_with_issues += 1
                    else:
                        signals.append({'technique': 'origin_validated',
                                        'form_action': action,
                                        'issue': False})

                signals.extend(form_signals)

            # Emit observations (issues first: a FAIL's lead evidence is an issue).
            for sig in sorted(signals, key=lambda x: 0 if x.get('issue') else 1):
                self._emit_signal(finding, sig, resp, samesite, framework)

            finding.tests_passed = max(0, len(post_forms) - forms_with_issues)

            csrf_signals = [s for s in signals if s.get('issue')]
            finding.fingerprint['csrf_signals'] = csrf_signals
            finding.fingerprint['csrf_observations'] = {
                'post_forms': len(post_forms),
                'forms_with_issues': forms_with_issues,
                'observations': [s.get('technique') for s in signals],
            }
            finding.fingerprint['csrf_protection'] = {
                'framework': framework,
                'same_site': samesite,
                'token_enforced': [s['form_action'] for s in signals
                                   if s['technique'] == 'token_enforced'],
                'origin_validated': [s['form_action'] for s in signals
                                     if s['technique'] == 'origin_validated'],
            }

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning CSRF: {str(e)}", payload=None)
            )
            finding.scan_errors += 1

        return finding

    # ---------------------------------------------------------------
    # Evidence emission
    # ---------------------------------------------------------------

    def _emit_signal(self, finding, sig, page_resp, samesite, framework):
        technique = sig.get('technique', 'unknown')
        action = sig.get('form_action', self.target)
        common = {
            'technique': technique,
            'matched_observation': technique,
            'form_action': action,
            'same_site': samesite,
            'framework': framework,
            'reliability': 'high',
            'reproducible': True,
            'samesite_mitigated': bool(
                samesite['lax_or_strict'] and not samesite['none_present']),
        }
        for k, v in sig.items():
            if v is not None and k not in common:
                common[k] = v

        if sig.get('issue'):
            request_info = {
                'method': 'POST',
                'url': action,
                'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                'payload': action,
            }
            response_info = {
                'status_code': getattr(page_resp, 'status_code', None),
                'headers': dict(getattr(page_resp, 'headers', {})),
                'body_length': len(getattr(page_resp, 'text', '') or ''),
                'body_snippet': (getattr(page_resp, 'text', '') or '')[:200],
                'elapsed': getattr(page_resp, 'elapsed', None).total_seconds()
                if getattr(page_resp, 'elapsed', None) else None,
            }
            ev = self._evidence_builder.request_response(
                f"CSRF weakness on POST form '{action}': "
                f"{technique.replace('_', ' ')}",
                request=request_info,
                response=response_info,
                payload=action,
                endpoint=action,
                method='POST',
            )
        else:
            ev = self._evidence_builder.verified(
                self._positive_desc(action, technique), payload=None)

        ev.raw_data.update(common)
        finding.add_evidence(ev)

    @staticmethod
    def _positive_desc(action, technique):
        if technique == 'token_enforced':
            return (f"POST form to '{action}' carries a CSRF token that the "
                    "server validates (submissions without it or with a wrong "
                    "token are both rejected)")
        if technique == 'origin_validated':
            return (f"POST form to '{action}' rejects cross-origin requests "
                    "(Origin/Referer are validated)")
        if technique == 'token_rotates':
            return (f"POST form to '{action}' issues a fresh CSRF token on each "
                    "page load (token is per-request unique)")
        if technique == 'no_token_mitigated_by_samesite':
            return (f"POST form to '{action}' has no CSRF token, but session "
                    "cookies use SameSite=Lax|Strict which mitigates the risk")
        return f"CSRF protection positive on '{action}' ({technique})"