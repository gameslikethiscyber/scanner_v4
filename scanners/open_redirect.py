import logging

from core.finding import Finding
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.OpenRedirect')

# Open Redirect scanner — evidence-only (v4.5.0, SOP Phase 3.6).
#
# The scanner never classifies: it only collects raw evidence for a set of
# independent redirect-vector techniques, each emitted as a confirmed
# observation only after repeated confirmation with a different payload.
# Manual accuracy upgrades over v3.3:
#
#   * Host-derived off-site classification (_is_off_site) — a redirect is only
#     an open redirect when the EFFECTIVE target host differs from the request's
#     own host. Same-host redirects are never flagged, even when the Location
#     string contains a suspicious domain (the biggest substring-scanner FP).
#   * Ambiguous-vector fallback — tokens that defeat a strict URL parser fall
#     back to an explicit-off-host substring check so detection is preserved.
#   * Richer evidence — every observation carries detection_method, target_host
#     and an off_site flag in raw_data + fingerprint; cross-validation lists the
#     confirmed techniques and the fingerprint records redirect_targets.
#
# Techniques: absolute, relative, protocol_relative, encoded, double_encoding,
# redirect_chain. The engine derives status/confidence/verification.


class OpenRedirectScanner(BaseScanner):

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Open Redirect"

        self.primary_payloads = {
            'absolute': ['https://evil.com/x', 'http://attacker.com/y'],
            'relative': ['/next=//evil.com', '//evil.com@'],
            'protocol_relative': ['//evil.com', '//attacker.com'],
            'encoded': ['https:%2F%2Fevil.com', '%2F%2Fevil.com'],
            'double_encoding': ['https:%252F%252Fevil.com', '%252F%252Fevil.com'],
        }

        self.off_host_hints = ('evil.com', 'attacker.com', 'attacker.net')

    def _own_host(self):
        try:
            from urllib.parse import urlparse
            return (urlparse(self.target).hostname or '').lower()
        except Exception:
            return ''

    # ------------------------------------------------------------------
    # scan() — evidence-only orchestration
    # ------------------------------------------------------------------

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            params = self.get_params()
            post_keys = list((self.post_data or {}).keys())
            has_params = bool(params or post_keys)

            if not has_params:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No URL query parameters or POST data found to test for "
                        "open redirect",
                        payload=None,
                    )
                )
                finding.tests_passed = 0
                return finding

            observations = []
            tests = 0
            techniques = set()

            for method, targets in (('GET', params), ('POST', post_keys)):
                if not targets:
                    continue
                obs, tested = self._check_redirects(targets, method)
                tests += tested
                for o in obs:
                    observations.append(o)
                    techniques.add(o['kind'])

            finding.tests_performed = tests
            finding.tests_run = tests

            observations.sort(key=lambda o: self._TECHNIQUE_ORDER.get(o['kind'], 9))

            if observations:
                for obs in observations:
                    self._emit_observation(finding, obs)

                if len(techniques) >= 2:
                    self._emit_cross_validation(finding, techniques)

                finding.tests_passed = max(0, tests - len(observations))
                finding.fingerprint['open_redirect_signals'] = [
                    {
                        'technique': o['kind'],
                        'parameter': o['param'],
                        'method': o['method'],
                        'payload': o['payload'],
                        'location': o['location'],
                        'target_host': o['target_host'],
                        'off_site': o['off_site'],
                    }
                    for o in observations
                ]
                hosts = sorted({o['target_host'] for o in observations
                                if o.get('target_host')})
                if hosts:
                    finding.fingerprint['redirect_targets'] = hosts
                finding.add_recommendation(
                    1, "Whitelist redirect targets",
                    "Open redirect lets an attacker craft a trusted link that "
                    "silently redirects victims to a malicious site.",
                    "Only redirect to relative paths or an explicit allowlist of "
                    "hosts; never reflect user input into the Location header.",
                    ["OWASP: Open Redirect", "PortSwigger: Open redirection"],
                )
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No open redirect detected. Tested {tests} payloads.",
                        payload=None,
                    )
                )
                finding.tests_passed = tests

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error during Open Redirect scan: {str(e)}", payload=None
                )
            )
            finding.scan_errors += 1

        return finding

    # Confirmed observations are emitted as structured request/response evidence
    # with the technique, matched rule and the observed Location header.
    def _emit_observation(self, finding, obs):
        resp = obs['resp']
        payload = obs['payload']
        param = obs['param']
        method = obs['method']

        request_info = {
            'method': method,
            'url': self._request_url(param, payload, method),
            'headers': dict(self.session.headers),
            'payload': payload,
        }
        response_info = {
            'status_code': resp.status_code,
            'headers': dict(resp.headers),
            'body_length': len(resp.text),
            'body_snippet': resp.text[:300],
            'location': obs['location'],
            'elapsed': resp.elapsed.total_seconds() if resp.elapsed else None,
        }

        ev = self._evidence_builder.request_response(
            obs['desc'],
            request=request_info,
            response=response_info,
            payload=payload,
            endpoint=self.target,
            parameter=param,
            method=method,
        )
        ev.raw_data.update({
            'technique': obs['kind'],
            'detection_method': obs.get('detection_method'),
            'matched_rule': obs.get('matched_rule'),
            'location': obs['location'],
            'target_host': obs.get('target_host'),
            'off_site': obs.get('off_site'),
            'reliability': obs.get('reliability', 'medium'),
            'reproducible': True,
            'confirm_payload': obs.get('confirm_payload'),
        })
        ev.verification_pass = 2
        ev.verification_method = "primary + confirm payloads"
        finding.add_evidence(ev)

    def _emit_cross_validation(self, finding, techniques):
        ev = self._evidence_builder.cross_validation(
            "Open redirect confirmed by multiple independent techniques "
            f"({', '.join(sorted(techniques))})",
            payload=None,
        )
        ev.verification_pass = len(techniques)
        ev.verification_method = f"{len(techniques)} independent techniques"
        finding.add_evidence(ev)

    # ------------------------------------------------------------------
    # Redirect checks
    # ------------------------------------------------------------------

    def _check_redirects(self, params, method='GET'):
        observations = []
        tested = 0
        for param in params:
            for technique, payloads in self.primary_payloads.items():
                confirmed = []
                for payload in payloads:
                    tested += 1
                    resp = self._send(param, payload, method, timeout=10)
                    if resp is None:
                        continue
                    location = self._decoded_location(resp)
                    if not location:
                        continue
                    off_site, host, _kind = self._is_off_site(location)
                    if off_site:
                        confirmed.append((payload, resp, location, host))
                if len(confirmed) >= 2:
                    payload, resp, location, host = confirmed[0]
                    observations.append({
                        'kind': technique,
                        'param': param,
                        'method': method,
                        'payload': payload,
                        'confirm_payload': confirmed[1][0],
                        'resp': resp,
                        'location': location,
                        'target_host': host,
                        'off_site': True,
                        'detection_method': 'location_host_classification',
                        'matched_rule': (
                            f"{technique} redirect off-host ({host}); "
                            f"reproduced with {confirmed[1][0]}"
                        ),
                        'reliability': 'high',
                        'desc': (
                            f"Open redirect ({technique}) in {method} parameter "
                            f"'{param}': '{payload}' redirected off-site to "
                            f"{location} (host {host}; reproduced with "
                            f"{confirmed[1][0]})"
                        ),
                    })
        return observations, tested

    def _decoded_location(self, resp):
        """Return the Location header, single- then double-decoded. A double-
        encoded vector is only self-evident after the second pass."""
        import urllib.parse
        raw = resp.headers.get('Location', '')
        if not raw:
            return ''
        once = urllib.parse.unquote(raw)
        twice = urllib.parse.unquote(once)
        if self._is_off_site(once)[0]:
            return once
        return twice

    def _effective_host(self, location):
        """Best-effort effective host from a Location string, normalizing the
        forms an application may parse (backslash as slash, protocol-relative,
        userinfo). Returns None when unparseable (relative path)."""
        import urllib.parse
        loc = location.replace('\\', '/')
        loc = loc.split('#', 1)[0]
        if loc.startswith('//'):
            loc = 'http:' + loc
        parsed = urllib.parse.urlparse(loc)
        netloc = parsed.netloc
        if '@' in netloc:
            netloc = netloc.rsplit('@', 1)[-1]
        host = netloc.split(':')[0].lower().strip('.')
        return host or None

    def _is_off_site(self, location):
        """(off_site, effective_host, kind). Off-site only when the effective
        target host differs from our own host. Same-host and relative redirects
        are never open redirects. Hostless/ambiguous vectors fall back to an
        explicit off-host substring so detection is preserved."""
        if not location:
            return False, '', 'none'
        own = self._own_host()
        host = self._effective_host(location)
        if host:
            return host != own, host, ('off' if host != own else 'same_host')
        # No parseable host: a same-origin relative path cannot be an open
        # redirect even if its query carries a suspicious absolute URL. Only
        # genuinely external-hosting forms (protocol-relative `//host`, bare
        # `evil.com@`, ...) fall back to the off-host substring check.
        loc = location.lstrip()
        if loc.startswith('/') and not loc.startswith('//'):
            return False, '', 'same_origin'
        lowered = loc.lower()
        return (any(h in lowered for h in self.off_host_hints), '',
                'hostless')

    # ------------------------------------------------------------------
    # Request helpers
    # ------------------------------------------------------------------

    _TECHNIQUE_ORDER = {
        'absolute': 0, 'relative': 1, 'protocol_relative': 2,
        'encoded': 3, 'double_encoding': 4, 'redirect_chain': 5,
    }

    def _send(self, param, payload, method, timeout=10):
        try:
            if method == 'GET':
                return self.session.get(
                    self.inject_payload(param, payload), timeout=timeout,
                    allow_redirects=False)
            data = self.post_data.copy()
            data[param] = payload
            return self.session.post(
                self.target, data=data, timeout=timeout, allow_redirects=False)
        except Exception:
            return None

    def _request_url(self, param, payload, method):
        if method == 'GET':
            return self.inject_payload(param, payload)
        return self.target