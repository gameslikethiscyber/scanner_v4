import re
import logging

from core.finding import Finding
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.XSS')

# XSS Detection scanner â€” evidence-only (v3, Batch 4 Part 2).
#
# The scanner collects independent observations per reflection context and never
# classifies. A single payload + single regex is never enough: a context is only
# confirmed when a primary payload is reflected into an executable location AND
# a second, distinct payload of the same family reproduces it:
#
#   - html_context       â€” payload lands as executable HTML (script / img /
#                          svg / body event handlers).
#   - attribute_context  â€” payload breaks out of an HTML attribute (quote
#                          breakout + event handler).
#   - js_context         â€” payload lands inside / breaks out of a <script> block
#                          or a JS event-handler expression.
#   - encoding_behaviour â€” a URL/HTML-encoded variant is decoded by the server
#                          into executable markup (weak output encoding). Support
#                          signal: only emitted alongside a confirmed context.
#
# The engine derives status/severity/confidence/verification; two or more
# confirmed contexts on a parameter add a cross-validation (verified) evidence.


class XSSScanner(BaseScanner):

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "XSS Detection"

# Context-aware payload selection (Phase 3.2). Each context carries a
        # primary set (executable markup) and a verification set (a *different*
        # construction of the same family). Payloads are ordered worst-first so
        # the most definitive case is confirmed first.
        self.context_payloads = {
            'html': {
                'script_tag': '<script>alert(1)</script>',
                'img_event': '<img src=x onerror=alert(1)>',
                'svg_event': '<svg onload=alert(1)>',
                'body_event': '<body onload=alert(1)>',
            },
            'attribute': {
                'double_quote_breakout': '"><img src=x onerror=alert(1)>',
                'single_quote_breakout': "'><img src=x onerror=alert(1)>",
                'autofocus_event': '" onfocus=alert(1) autofocus x="',
                'unquoted_event': "' onfocus=alert(1) autofocus x='",
            },
            'javascript': {
                'script_breakout': '</script><script>alert(1)</script>',
                'semicolon_breakout': "';alert(1);//",
                'double_quote_breakout': '";alert(1);//',
                'tpl_literal_breakout': '${alert(1)}',
            },
        }

        # Primary payloads mirror the existing families so behaviour is unchanged
        # for the public surface while new payloads broaden coverage.
        self.families = {
            'html': {
                'payloads': [
                    '<script>alert(1)</script>',
                    '<img src=x onerror=alert(1)>',
                    '<svg onload=alert(1)>',
                    '<body onload=alert(1)>',
                ],
                # Context patterns tie the reflected marker to an *executable*
                # location: the marker must sit inside the tag/script it is
                # delivered by, not merely appear elsewhere in the page (a page
                # with its own event handlers must not trip a reflection-only
                # finding). Escaped output (`&lt;script&gt;`) never matches.
                'context': [
                    r'<script[^>]*>\s*alert\s*\(',
                    r'<img[^>]*\sonerror\s*=\s*["\']?alert\s*\(',
                    r'<svg[^>]*\sonload\s*=\s*["\']?alert\s*\(',
                    r'<body[^>]*\sonload\s*=\s*["\']?alert\s*\(',
                ],
                'markers': (r'alert\(1\)',),
            },
            'attribute': {
                'payloads': [
                    '"><img src=x onerror=alert(1)>',
                    "'><img src=x onerror=alert(1)>",
                    '" onfocus=alert(1) autofocus x="',
                    "' onfocus=alert(1) autofocus x='",
                    '"><svg onload=alert(1)>',
                ],
                # Only literal quote breakouts / unquoted injections count: an
                # escaped `&quot;`/`&gt;` cannot break out of an attribute.
                'context': [
                    r'["\']\s*on\w+\s*=\s*["\']?alert\s*\(',
                    r'["\']\s*>\s*<[a-z][^>]*\son\w+\s*=\s*["\']?alert\s*\(',
                    r'(?:src|href)\s*=\s*["\']?[^"\']*alert\s*\(',
                ],
                'markers': (r'alert\(1\)', r'onerror=alert', r'onfocus=alert',
                            r'onload=alert'),
            },
            'javascript': {
                'payloads': [
                    '</script><script>alert(1)</script>',
                    "';alert(1);//",
                    '";alert(1);//',
                    '${alert(1)}',
                ],
                'context': [
                    r'<script[^>]*>[^<]*alert\s*\(',
                    r'<script[^>]*>[^<]*;\s*alert\s*\(',
                    r'</script>\s*<script[^>]*>\s*alert\s*\(',
                    r'\$\{?\s*alert\s*\(',
                    r'on\w+\s*=\s*["\']?[^"\']*alert\s*\(',
                ],
                'markers': (r'alert\(1\)', r'</script>\s*<script', r'\$\{alert\('),
            },
        }

        # Concrete sink rules per family (context-aware evidence). The reported
        # sink tells the reader exactly WHERE the payload executed.
        self.sink_rules = {
            'html': [
                ('script_tag', r'<script[^>]*>\s*alert\s*\('),
                ('img_event', r'<img[^>]*\sonerror\s*='),
                ('svg_event', r'<svg[^>]*\sonload\s*='),
                ('body_event', r'<body[^>]*\sonload\s*='),
            ],
            'attribute': [
                ('quote_breakout', r'["\']\s*on\w+\s*='),
                ('unquoted_event', r'(?:src|href)\s*=\s*["\']?[^"\']*alert\s*\('),
            ],
            'javascript': [
                ('script_breakout', r'</script>\s*<script'),
                ('js_string_breakout', r';\s*alert\s*\('),
                ('template_breakout', r'\$\{\s*alert\s*\('),
            ],
        }

        # Encoded variants â€” a decoded reflection here proves the server
        # decodes user input before emitting it (weak output encoding).
        self.encoded_payloads = [
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
        ]

        # DOM-XSS indicators: dangerous JavaScript sinks that, when fed by a
        # reflected parameter inside an inline <script>, signal a possible DOM
        # source. Without a rendering engine this is only an *indicative*
        # support signal (never a standalone finding; no browser automation).
        self.dom_sinks = [
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'document\.write\s*\(',
            r'\.insertAdjacentHTML\s*\(',
            r'\beval\s*\(',
            r'\.setAttribute\s*\(',
            r'\.textContent\s*=',
            r'\.href\s*=',
            r'\.location\s*=' ,
        ]

    # ------------------------------------------------------------------
    # scan() â€” evidence-only orchestration
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
                        "No URL parameters or POST data found to test for XSS",
                        payload=None,
                    )
                )
                finding.tests_passed = 0
                return finding

            core_observations = []
            support_observations = []
            tests = 0
            contexts = set()

            for method, targets in (('GET', params), ('POST', post_keys)):
                if not targets:
                    continue
                for family_name in ('html', 'attribute', 'javascript'):
                    for param in targets:
                        obs, tested = self._test_family(param, family_name, method)
                        tests += tested
                        if obs:
                            core_observations.append(obs)
                            contexts.add(family_name)

            # Encoded-decoding is only meaningful as a support signal once a
            # confirmed context exists (never a standalone finding).
            if core_observations:
                for method, targets in (('GET', params), ('POST', post_keys)):
                    if not targets:
                        continue
                    for param in targets:
                        enc = self._test_encoded(param, method)
                        tests += enc['tested'] if enc else 0
                        if enc and enc['obs']:
                            support_observations.append(enc['obs'])
                            break
                    if support_observations:
                        break

                # Stored-persistence probe: only after a confirmed reflected
                # context (independent source-of-truth). Bounded to one POST +
                # one payload-free GET.
                if not any(o['context'] == 'stored_persistence' for o in support_observations):
                    for obs in core_observations:
                        stored = self._check_stored(obs)
                        tests += 1
                        if stored:
                            support_observations.append(stored)
                            break

                # DOM-source indicative: static scan of the response
                # containing the reflected payload for a sink reached by the
                # reflected value inside an inline <script>. No rendering.
                for obs in core_observations:
                    dom = self._check_dom(obs)
                    if dom:
                        support_observations.append(dom)

            finding.tests_performed = tests
            finding.tests_run = tests

            if core_observations:
                for obs in core_observations:
                    self._emit_observation(finding, obs)
                for obs in support_observations:
                    self._emit_support(finding, obs)

                if len(contexts) >= 2:
                    self._emit_cross_validation(finding, contexts)

                finding.tests_passed = max(0, tests - len(core_observations))
                finding.fingerprint['xss_signals'] = [
                    {
                        'context': o['context'],
                        'sink': o.get('sink'),
                        'parameter': o['param'],
                        'method': o['method'],
                        'location': o.get('reflection_location'),
                    }
                    for o in core_observations
                ]
                finding.fingerprint['reflected_params'] = sorted(
                    {o['param'] for o in core_observations}
                )
                support_named = {o['context'] for o in support_observations}
                if support_named:
                    finding.fingerprint['support_signals'] = sorted(support_named)
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No XSS detected. Tested {tests} payloads.",
                        payload=None,
                    )
                )
                finding.tests_passed = tests

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error during XSS scan: {str(e)}", payload=None
                )
            )
            finding.scan_errors += 1

        return finding

    def _emit_observation(self, finding, obs):
        resp = obs['resp']
        method = obs['method']
        param = obs['param']
        payload = obs['payload']

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
            'context': obs['context'],
            'sink': obs.get('sink'),
            'reflection_location': obs.get('reflection_location'),
            'matched_rule': obs.get('matched_rule'),
            'reliability': obs.get('reliability', 'medium'),
            'reproducible': True,
            'verify_payload': obs.get('verify_payload'),
        })
        ev.verification_pass = 2
        ev.verification_method = "primary + verify payloads"
        finding.add_evidence(ev)

    def _emit_support(self, finding, obs):
        # Support signals use `likely` (never `possible`): a `possible` evidence
        # item would cap the finding's confidence at 60 and undercut the
        # confirmed-context confidence (engine cap chain). A DOM-source
        # *indicative* probe is kept at `possible` only when it is strictly a
        # non-executing heuristic and always accompanied by a confirmed context.
        context = obs['context']
        if context == 'dom_source' and obs.get('indicative'):
            ev = self._evidence_builder.possible(
                obs['desc'],
                payload=obs['payload'],
                endpoint=self.target,
                parameter=obs['param'],
                method=obs['method'],
            )
        else:
            ev = self._evidence_builder.likely(
                obs['desc'],
                payload=obs['payload'],
                endpoint=self.target,
                parameter=obs['param'],
                method=obs['method'],
            )
        ev.raw_data.update({
            'context': context,
            'matched_rule': obs.get('matched_rule'),
            'reliability': obs.get('reliability', 'medium'),
            'reproducible': True,
            'persisted': obs.get('persisted'),
            'sink': obs.get('sink'),
        })
        finding.add_evidence(ev)

    def _emit_cross_validation(self, finding, contexts):
        ev = self._evidence_builder.cross_validation(
            "XSS confirmed in multiple independent reflection contexts "
            f"({', '.join(sorted(contexts))})",
            payload=None,
        )
        ev.verification_pass = len(contexts)
        ev.verification_method = f"{len(contexts)} independent contexts"
        finding.add_evidence(ev)

    # ------------------------------------------------------------------
    # Family detection
    # ------------------------------------------------------------------

    def _test_family(self, param, family_name, method):
        """Return (observation | None, tests_run) for one param+family."""
        family = self.families[family_name]
        tested = 0
        for i, payload in enumerate(family['payloads']):
            resp = self._send(param, payload, method, timeout=10)
            tested += 1
            if resp is None or not self._family_hit(resp.text, family):
                continue
            # Repeated confirmation with a second, distinct payload.
            for j, verify_payload in enumerate(family['payloads']):
                if j == i:
                    continue
                verify_resp = self._send(param, verify_payload, method, timeout=10)
                tested += 1
                if verify_resp is None or not self._family_hit(verify_resp.text, family):
                    continue
                location = self._reflection_location(resp.text, family['markers'])
                sink = self._classify_sink(family_name, resp.text)
                return ({
                    'context': family_name,
                    'sink': sink,
                    'param': param,
                    'method': method,
                    'payload': payload,
                    'verify_payload': verify_payload,
                    'resp': resp,
                    'reflection_location': location,
                    'matched_rule': (
                        f"{family_name} context confirmation via 2 independent payloads"
                    ),
                    'reliability': 'high',
                    'desc': (
                        f"XSS reflected in {method} parameter '{param}' in a "
                        f"{family_name} context (multi-payload confirmed)"
                    ),
                }, tested)
        return None, tested

    def _test_encoded(self, param, method):
        """Return {'obs', 'tested'} when an encoded payload is decoded by the
        server into executable markup (support signal)."""
        tested = 0
        for payload in self.encoded_payloads:
            resp = self._send(param, payload, method, timeout=10)
            tested += 1
            if resp is None:
                continue
            if self._family_hit(resp.text, self.families['html']):
                return {
                    'obs': {
                        'context': 'encoding_behaviour',
                        'param': param,
                        'method': method,
                        'payload': payload,
                        'matched_rule': (
                            "URL/HTML-encoded payload decoded by the server into "
                            "executable markup (weak output encoding)"
                        ),
                        'desc': (
                            f"Encoded XSS payload in {method} parameter '{param}' "
                            f"was decoded into executable markup by the server "
                            f"(weak output encoding)"
                        ),
                    },
                    'tested': tested,
                }
        return {'obs': None, 'tested': tested}

    # ------------------------------------------------------------------
    # Reflection helpers
    # ------------------------------------------------------------------

    def _family_hit(self, body, family):
        """Reflection AND executable context must both hold (no single-regex
        confirmation â€” the marker and the context regex are independent checks).

        Server-side HTML entity encoding turns our payload into literal text
        (`&lt;script&gt;`, `&quot;...&quot;`). Such escaped tags are inert in the
        browser, so we strip `&lt;...&gt;` spans (the enclosing escaped element)
        before matching: an escaped payload must never satisfy a reflection-only
        finding even though the words `src=`, `onerror=` and `alert(1)` still
        survive entity encoding."""
        body = self._strip_escaped(body)
        marker_hit = any(
            re.search(marker, body, re.IGNORECASE) for marker in family['markers']
        )
        if not marker_hit:
            return False
        return any(
            re.search(pattern, body, re.IGNORECASE) for pattern in family['context']
        )

    _ESCAPED_TAG = re.compile(
        r'&(?:lt|#60|#x3c);\s*(.*?)\s*&(?:gt|#62|#x3e);', re.IGNORECASE | re.DOTALL
    )

    def _strip_escaped(self, body):
        """Remove entity-escaped tags from a page so inert (escaped) markup
        cannot be misread as executable payload reflection."""
        try:
            return self._ESCAPED_TAG.sub('', body or '')
        except Exception:
            return body or ''

    def _classify_sink(self, family_name, body):
        """Return the concrete sink where the payload executed (context-aware)."""
        for name, pattern in self.sink_rules.get(family_name, []):
            if re.search(pattern, body, re.IGNORECASE):
                return name
        return family_name

    def _reflection_location(self, body, markers):
        """Return a short snippet around the first reflected marker."""
        for marker in markers:
            match = re.search(marker, body, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 60)
                end = min(len(body), match.end() + 60)
                return body[start:end].replace('\n', ' ')
        return body[:120]

    def _check_stored(self, obs):
        """Stored-persistence probe (support, never standalone).

        After a confirmed reflected context, this attempts to persist the
        payload (POST) and reads the page back WITHOUT the payload in the
        request (GET) to see whether the marker survived. Bounded to one POST
        + one payload-free GET.
        """
        try:
            family = self.families[obs['context']]
            # Persist attempt: submit the payload as POST data to the target.
            self.session.post(
                self.target,
                data={obs['param']: obs['payload']},
                timeout=10,
            )
            # Read back with no payload in the request -> persistence proof.
            read = self.session.get(self.target, timeout=10)
            if read is None:
                return None
            persisted = any(
                re.search(marker, read.text, re.IGNORECASE)
                for marker in family['markers']
            )
            if not persisted:
                return None
            return {
                'context': 'stored_persistence',
                'param': obs['param'],
                'method': obs['method'],
                'payload': obs['payload'],
                'persisted': persisted,
                'matched_rule': (
                    "XSS payload persisted on a subsequent payload-free read "
                    "(stored XSS behaviour)"
                ),
                'reliability': 'medium',
                'desc': (
                    f"Stored XSS behaviour for {obs['method']} parameter "
                    f"'{obs['param']}': the reflected payload persisted on a "
                    f"later page fetch with no payload in the request"
                ),
            }
        except Exception:
            return None

    def _check_dom(self, obs):
        """DOM-source indicative (support, never standalone). Without a
        rendering engine we cannot prove execution; we detect a reflected
        parameter whose value also flows into a dangerous DOM sink inside an
        inline <script> block. Conservative: requires the sink keyword AND the
        reflected payload in the SAME <script>...</script> block."""
        try:
            resp = obs.get('resp')
            if resp is None:
                return None
            body = resp.text or ''
            blocks = re.findall(r'<script\b[^>]*>(.*?)</script>', body,
                                re.DOTALL | re.IGNORECASE)
            if not blocks:
                return None
            marker = self.families[obs['context']]['markers'][0]
            for block in blocks:
                if not re.search(marker, block, re.IGNORECASE):
                    continue
                for sink_pat in self.dom_sinks:
                    if re.search(sink_pat, block, re.IGNORECASE):
                        return {
                            'context': 'dom_source',
                            'parsed': True,
                            'indicative': True,
                            'param': obs['param'],
                            'method': obs['method'],
                            'payload': obs['payload'],
                            'sink': sink_pat,
                            'matched_rule': (
                                "reflected value flows into a DOM sink "
                                "within an inline <script> (indicative)"
                            ),
                            'reliability': 'low',
                            'desc': (
                                f"DOM-XSS indicator for {obs['method']} parameter "
                                f"'{obs['param']}': the reflected value appears in "
                                "an inline <script> block containing a dangerous "
                                "DOM sink - manual verification recommended"
                            ),
                        }
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Request helpers
    # ------------------------------------------------------------------

    def _send(self, param, payload, method, timeout=10):
        try:
            if method == 'GET':
                return self.session.get(self.inject_payload(param, payload), timeout=timeout)
            data = self.post_data.copy()
            data[param] = payload
            return self.session.post(self.target, data=data, timeout=timeout)
        except Exception:
            return None

    def _request_url(self, param, payload, method):
        if method == 'GET':
            return self.inject_payload(param, payload)
        return self.target
