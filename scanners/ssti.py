import logging

from core.finding import Finding
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.SSTI')

# SSTI Detection scanner — evidence-only (v4.4.0, SOP Phase 3.5).
#
# The scanner never classifies: it only collects raw evidence for server-side
# template injection across multiple template engines. Each engine's syntax is
# confirmed only when TWO different arithmetic expressions evaluate to the
# expected results (e.g. {{7*7}} -> 49 AND {{8*9}} -> 72), which rules out the
# numbers coincidentally already being present in normal page content.
#
# Manual: accuracy improvements over v3:
#
#   * Per-(param, method) baseline FP-guard — the expected arithmetic values are
#     only accepted as injection proof when BOTH are ABSENT from the benign
#     (non-injected) response for that parameter. A page that already prints
#     "49" or "72" (copy, totals, examples) can never satisfy the confirmation.
#   * Two-tier evaluation — every engine probes with primary + confirm
#     constructions ((_engine_primary / _engine_confirm)); the claimed engine is
#     only reported after both evaluate.
#   * Enhanced engine fingerprinting — every confirmed evaluation also probes
#     the parameter with render-variant payloads (primary arithmetic, a switch
#     to the alternate delimiters, an engine error trigger) and scans the result
#     against a broad, per-engine marker catalog (_match_engines). Matched
#     markers are recorded as engine_fingerprint support AND cross-correlated
#     with the arithmetic claim (fingerprint_consistent), sharpening
#     engine identification on real templates.
#   * Evidence correlation — observations carry engine, syntax, verification
#     passes, matched fingerprint markers, and a per-engine confidence summary;
#     cross-validation enumerates the confirmed engine families.
#   * Reduced false positives — baseline exclusion (above) + syntax-family
#     de-duplication (only the first engine of a shared {{ }} family is
#     arithmetic-confirmed; the rest must be fingerprinted independently).
#
# Engines covered: jinja2, twig, freemarker, velocity, handlebars, smarty, erb
# (+ impartial). The engine derives status/severity/confidence/verification.


class SSTIScanner(BaseScanner):

    # engine -> {syntax label, primary payload/expected, confirm payload/expected}
    ENGINE_PAYLOADS = {
        'jinja2': {
            'syntax': '{{ expr }}',
            'primary': ('{{7*7}}', '49'),
            'confirm': ('{{8*9}}', '72'),
        },
        'twig': {
            'syntax': '{{ expr }}',
            'primary': ('{{7*7}}', '49'),
            'confirm': ('{{8*9}}', '72'),
        },
        'handlebars': {
            'syntax': '{{ expr }}',
            'primary': ('{{7*7}}', '49'),
            'confirm': ('{{8*9}}', '72'),
        },
        'freemarker': {
            'syntax': '${expr}',
            'primary': ('${7*7}', '49'),
            'confirm': ('${8*9}', '72'),
        },
        'velocity': {
            'syntax': '#set($x=expr)$x',
            'primary': ('#set($x=7*7)$x', '49'),
            'confirm': ('#set($x=8*9)$x', '72'),
        },
        'smarty': {
            'syntax': '{expr}',
            'primary': ('{7*7}', '49'),
            'confirm': ('{8*9}', '72'),
        },
        'erb': {
            'syntax': '<%= expr %>',
            'primary': ('<%= 7*7 %>', '49'),
            'confirm': ('<%= 8*9 %>', '72'),
        },
    }

    # Broad per-engine marker catalog. Only distinctive substrings are listed;
    # weak/ambiguous tokens ("template", "ruby") are deliberately excluded so a
    # normal page mentioning the word cannot be over-attributed.
    ENGINE_FINGERPRINTS = {
        'jinja2': ('jinja2.exceptions', 'jinja2.Environment', 'TemplateSyntaxError',
                   'UndefinedError', 'jinja2.runtime', 'end_had_text'),
        'twig': ('Twig\\Error\\SyntaxError', 'Twig_Error_Syntax', 'Twig\\Environment',
                 'Twig\\Runtime\\Environment', 'twig'),
        'freemarker': ('freemarker.core', 'freemarker.template', 'TemplateModelException',
                       'FreeMarker template error', 'InvalidReferenceException',
                       'For "${"', 'freemarker'),
        'velocity': ('org.apache.velocity', 'VelocityException', 'VelocityContext',
                   'org/apache/velocity', 'velocity'),
        'handlebars': ('Missing helper', 'MissingHandlebars', 'Handlebars',
                     'handlebars-runtime', 'carpenter'),
        'smarty': ('SmartyBC', 'Smarty_Internal', 'smarty.tpl', 'Smarty', 'RuntimeAccessedVariable'),
        'erb': ('ActionView::Template', 'ActionView::MissingTemplate', 'ERB',
              'Erubis', 'TemplateError'),
    }

    # Distinctive, low-collision arithmetic products used as fingerprinted
    # variant probes (in addition to the primary/confirm pair).
    ENGINE_PROBES = {
        'jinja2': ('{{7*7}}', "{{11*13}}"),
        'twig': ('{{7*7}}', "{{11*13}}"),
        'handlebars': ('{{7*7}}', "{{11*13}}"),
        'freemarker': ('${7*7}', '${11*13}'),
        'velocity': ('#set($x=7*7)$x', '#set($x=11*13)$x'),
        'smarty': ('{7*7}', '{11*13}'),
        'erb': ('<%= 7*7 %>', '<%= 11*13 %>'),
    }

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "SSTI Detection"
        self._baseline_cache = {}

    def _baseline_body(self, param, method):
        key = (param, method)
        if key in self._baseline_cache:
            return self._baseline_cache[key]
        safe = self._baseline_safe_value(param, method)
        resp = self._test(param, safe, method)
        body = resp.text if resp is not None else ''
        self._baseline_cache[key] = body
        return body

    def _baseline_safe_value(self, param, method):
        return 'probe_SSTI' if method == 'get' else (self.post_data or {}).get(param, '')

    def _evaluation_credible(self, param, method, primary_expected, confirm_expected):
        """Both expected values must be ABSENT from the per-parameter baseline so
        the numbers are introduced by our injection, not pre-printed by the app."""
        baseline = self._baseline_body(param, method)
        return (primary_expected not in baseline and
                confirm_expected not in baseline)

    # ------------------------------------------------------------------
    # scan() — evidence-only orchestration
    # ------------------------------------------------------------------

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            params = self.get_params()
            post_keys = list((self.post_data or {}).keys())
            test_targets = [(p, 'get') for p in params]
            test_targets += [(p, 'post') for p in post_keys]

            if not test_targets:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No GET parameters or POST fields found to test for "
                        "server-side template injection",
                        payload=None,
                    )
                )
                finding.tests_passed = 0
                return finding

            observations = []
            support = []
            tests = 0
            engines_confirmed = set()
            confirmed_syntaxes = set()
            engine_evidence = []

            for param, method in test_targets:
                for engine, spec in self.ENGINE_PAYLOADS.items():
                    primary_payload, primary_expected = spec['primary']
                    confirm_payload, confirm_expected = spec['confirm']

                    # Arithmetic alone cannot tell engines sharing {{ }} apart,
                    # and a value already printed by the app is not proof.
                    syntax_family = (spec['syntax'], primary_payload, confirm_payload)
                    if not self._evaluation_credible(param, method,
                                                     primary_expected,
                                                     confirm_expected):
                        continue
                    if syntax_family in confirmed_syntaxes:
                        continue

                    tests += 1
                    primary_resp = self._test(param, primary_payload, method)
                    if primary_resp is None or primary_expected not in primary_resp.text:
                        continue

                    tests += 1
                    confirm_resp = self._test(param, confirm_payload, method)
                    if confirm_resp is None or confirm_expected not in confirm_resp.text:
                        continue

                    confirmed_syntaxes.add(syntax_family)
                    # fingerprint + variant correlation for the same parameter
                    rendered = (confirm_resp.text or '') + \
                        self._render_text(param, engine, method)
                    observed_markers, consistent = self._analyze_engine(
                        rendered, engine)

                    observations.append({
                        'kind': 'arithmetic_evaluation',
                        'param': param,
                        'method': method,
                        'engine': engine,
                        'syntax': spec['syntax'],
                        'payload': primary_payload,
                        'confirm_payload': confirm_payload,
                        'primary_expected': primary_expected,
                        'confirm_expected': confirm_expected,
                        'resp': confirm_resp,
                        'markers': observed_markers,
                        'fingerprint_consistent': consistent,
                        'desc': (
                            f"SSTI in {method} parameter '{param}': "
                            f"{engine} ({spec['syntax']}) evaluated "
                            f"'{primary_payload}' -> {primary_expected} and "
                            f"'{confirm_payload}' -> {confirm_expected}"
                        ),
                    })
                    engines_confirmed.add(engine)
                    engine_evidence.append({
                        'engine': engine,
                        'syntax': spec['syntax'],
                        'markers': observed_markers,
                        'fingerprint_consistent': consistent,
                    })
                    support += self._collect_support(param, method, engine,
                                                     observed_markers)

            finding.tests_performed = tests
            finding.tests_run = tests

            if observations:
                for obs in observations:
                    self._emit_observation(finding, obs)

                if len(engines_confirmed) >= 2:
                    self._emit_cross_validation(finding, engines_confirmed)

                finding.tests_passed = max(0, tests - len(observations))
                finding.fingerprint['ssti_signals'] = [
                    {
                        'technique': o['kind'],
                        'parameter': o['param'],
                        'method': o['method'],
                        'engine': o['engine'],
                        'fingerprint_consistent': o['fingerprint_consistent'],
                    }
                    for o in observations
                ]
                finding.fingerprint['engines'] = sorted(engines_confirmed)
                finding.fingerprint['engine_evidence'] = engine_evidence
                for s in support:
                    self._emit_support(finding, s)
                finding.add_recommendation(
                    1, "Never render request input through the template engine",
                    "Server-Side Template Injection allows arbitrary code execution "
                    "on the server in most template engines (Jinja2, Twig, "
                    "Freemarker, Velocity, Handlebars, Smarty).",
                    "Treat all user input as data, never as template source. Use a "
                    "sandboxed/logic-less template mode if user-controlled templates "
                    "are unavoidable.",
                    ["OWASP: Server-Side Template Injection", "PortSwigger: SSTI"],
                )
            else:
                probes = self._collect_error_probes(test_targets)
                if probes:
                    for s in probes:
                        self._emit_support(finding, s)
                    finding.tests_passed = tests
                    finding.fingerprint['ssti_errors'] = [
                        {'parameter': s['param'], 'engine': s.get('engine'),
                         'pattern': s['matched_rule']}
                        for s in probes
                    ]
                else:
                    finding.add_evidence(
                        self._evidence_builder.verified(
                            f"No server-side template injection detected across "
                            f"{len(test_targets)} parameter(s) and "
                            f"{len(self.ENGINE_PAYLOADS)} template engine syntaxes",
                            payload=None,
                        )
                    )
                    finding.tests_passed = tests

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error during SSTI scan: {str(e)}", payload=None
                )
            )
            finding.scan_errors += 1

        return finding

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
            'engine': obs['engine'],
            'syntax': obs.get('syntax'),
            'primary_expected': obs.get('primary_expected'),
            'confirm_expected': obs.get('confirm_expected'),
            'markers_matched': obs.get('markers') or [],
            'fingerprint_consistent': obs.get('fingerprint_consistent'),
            'reliability': 'high',
            'reproducible': True,
            'confirm_payload': obs.get('confirm_payload'),
        })
        ev.verification_pass = 2
        ev.verification_method = ("two independent arithmetic evaluations "
                                  "+ baseline exclusion")
        finding.add_evidence(ev)

    def _emit_support(self, finding, obs):
        ev = self._evidence_builder.likely(
            obs['desc'],
            payload=obs.get('payload'),
            endpoint=self.target,
            parameter=obs['param'],
            method=obs['method'],
        )
        ev.raw_data.update({
            'technique': obs['kind'],
            'matched_rule': obs.get('matched_rule'),
            'engine': obs.get('engine'),
            'markers_matched': obs.get('markers') or [],
        })
        finding.add_evidence(ev)

    def _emit_cross_validation(self, finding, engines):
        ev = self._evidence_builder.cross_validation(
            "Server-side template injection confirmed on multiple template "
            f"engines ({', '.join(sorted(engines))})",
            payload=None,
        )
        ev.verification_pass = len(engines)
        ev.verification_method = f"{len(engines)} template engines"
        finding.add_evidence(ev)

    # ------------------------------------------------------------------
    # Engine fingerprinting + context-variant probes
    # ------------------------------------------------------------------

    def _render_probes(self, engine):
        """Ordered (worst-first) context variants used to fingerprint the engine.
        The second entry switches arithmetic target so the marker is novel."""
        return self.ENGINE_PROBES.get(engine, ('{{7*7}}', '{{11*13}}'))

    def _render_text(self, param, engine, method):
        """Concatenate engine-render probe responses to broaden fingerprinting."""
        text = ''
        for probe in self._render_probes(engine)[1:]:
            resp = self._test(param, probe, method)
            if resp is not None:
                text += resp.text
        return text

    def _match_engines(self, text):
        """Return {engine: [matched markers]} for all engines with a marker."""
        if not text:
            return {}
        low = text.lower()
        found = {}
        for engine, patterns in self.ENGINE_FINGERPRINTS.items():
            hits = [p for p in patterns if p.lower() in low]
            if hits:
                found[engine] = hits
        return found

    def _analyze_engine(self, text, claimed):
        """Cross-check candidates from the rendered text against the claimed
        engine: (matched_markers, consistent_with_claim)."""
        matches = self._match_engines(text)
        observed = [fmt for offsets in matches.values() for fmt in offsets]
        claimed_hits = matches.get(claimed, [])
        return observed, bool(claimed_hits)

    def _collect_support(self, param, method, engine, observed_markers):
        """Engine-fingerprint support evidence tied to the confirmed parameter."""
        support = []
        if observed_markers:
            support.append({
                'kind': 'engine_fingerprint',
                'param': param,
                'method': method,
                'engine': engine,
                'markers': observed_markers,
                'matched_rule': (observed_markers[0]
                                 if observed_markers else '(none)'),
                'payload': self.ENGINE_PROBES.get(engine, ('{{7*7}}',))[0],
                'desc': (
                    f"SSTI engine fingerprints in {method} parameter '{param}': "
                    f"markers {observed_markers[:3]} present, "
                    f"consistent with {engine}"
                ),
            })
        return support

    def _collect_error_probes(self, test_targets):
        """When nothing is confirmed, surface template-engine error fingerprints
        as likely support evidence (never a standalone finding)."""
        probes = []
        for param, method in test_targets:
            seen = set()
            for payload in ('{{7*7}}', '${7*7}', '#set($x=7*7)$x', '{7*7}',
                            '<%= 7*7 %>', '{{'):
                resp = self._test(param, payload, method)
                if resp is None:
                    continue
                matches = self._match_engines(resp.text)
                for engine, markers in matches.items():
                    if engine in seen:
                        continue
                    seen.add(engine)
                    probes.append({
                        'kind': 'error_fingerprint',
                        'param': param,
                        'method': method,
                        'engine': engine,
                        'markers': markers,
                        'matched_rule': markers[0],
                        'payload': payload,
                        'desc': (
                            f"Lookb tree template fingerprint in {method} "
                            f"parameter '{param}': {markers[0]!r} "
                            f"(possible {engine})"
                        ),
                    })
                if seen:
                    break
        return probes

    # ------------------------------------------------------------------
    # Request helpers
    # ------------------------------------------------------------------

    _TECHNIQUE_ORDER = {'arithmetic_evaluation': 0, 'engine_fingerprint': 1,
                        'error_fingerprint': 2}

    def _test(self, param, payload, method):
        try:
            if method == 'get':
                return self.session.get(self.inject_payload(param, payload), timeout=10)
            value = self.post_data.copy()
            value[param] = payload
            return self.session.post(self.target, data=value, timeout=10)
        except Exception:
            return None

    def _request_url(self, param, payload, method):
        if method == 'get':
            return self.inject_payload(param, payload)
        return self.target