import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.SSTI')


class SSTIScanner(BaseScanner):
    """
    Server-Side Template Injection scanner.

    Tests each GET parameter (and POST field, if post_data is supplied)
    with math-expression payloads for the most common template engines.
    A finding is only reported once TWO different math results are
    confirmed for the SAME engine syntax (e.g. {{7*7}} -> 49 AND
    {{8*9}} -> 72), which rules out the number coincidentally already
    being present in normal page content.
    """

    ENGINE_PAYLOADS = {
        'jinja2/twig': {'primary': ('{{7*7}}', '49'), 'confirm': ('{{8*9}}', '72')},
        'freemarker':  {'primary': ('${7*7}', '49'),  'confirm': ('${8*9}', '72')},
        'velocity':    {'primary': ('#set($x=7*7)$x', '49'), 'confirm': ('#set($x=8*9)$x', '72')},
        'erb_ruby':    {'primary': ('<%= 7*7 %>', '49'), 'confirm': ('<%= 8*9 %>', '72')},
        'smarty':      {'primary': ('{7*7}', '49'),    'confirm': ('{8*9}', '72')},
    }

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "SSTI Detection"

    def _get_baseline_text(self):
        resp, _ = self.get_baseline()
        return resp.text if resp is not None else ""

    def _test_param_get(self, param, payload):
        try:
            test_url = self.inject_payload(param, payload)
            return self.session.get(test_url, timeout=10)
        except Exception:
            return None

    def _test_post(self, param, payload):
        try:
            data = self.post_data_with_payload(param, payload)
            return self.session.post(self.target, data=data, timeout=10)
        except Exception:
            return None

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            params = self.get_params()
            test_targets = [(p, 'get') for p in params]
            if self.post_data:
                test_targets += [(p, 'post') for p in self.post_data.keys()]

            if not test_targets:
                finding.status = Status.SKIPPED
                finding.skip_reason = "No GET parameters or POST fields found to test for SSTI"
                return finding

            baseline_text = self._get_baseline_text()
            confirmed_count = 0

            for param, method in test_targets:
                for engine, payloads in self.ENGINE_PAYLOADS.items():
                    primary_payload, primary_expected = payloads['primary']
                    confirm_payload, confirm_expected = payloads['confirm']

                    if primary_expected in baseline_text:
                        continue  # avoid false positives on pages that already print this number

                    primary_resp = (
                        self._test_param_get(param, primary_payload) if method == 'get'
                        else self._test_post(param, primary_payload)
                    )
                    if primary_resp is None or primary_expected not in primary_resp.text:
                        continue

                    confirm_resp = (
                        self._test_param_get(param, confirm_payload) if method == 'get'
                        else self._test_post(param, confirm_payload)
                    )
                    if confirm_resp is None or confirm_expected not in confirm_resp.text:
                        continue

                    self.capture_http_evidence(
                        finding,
                        f"SSTI confirmed in '{param}' ({method.upper()}) — {engine} syntax evaluated "
                        f"'{primary_payload}' to {primary_expected} and '{confirm_payload}' to {confirm_expected}",
                        primary_resp, payload=primary_payload, parameter=param, method=method.upper(),
                    )
                    self.add_payload_evidence(finding, primary_payload, param)
                    finding.confirmations += 2
                    finding.cross_validated = True
                    confirmed_count += 1
                    break  # no need to try other engine syntaxes on this param

            finding.tests_performed = len(test_targets) * len(self.ENGINE_PAYLOADS)
            finding.tests_run = finding.tests_performed

            if confirmed_count:
                finding.status = Status.FAIL
                finding.severity = Severity.CRITICAL
                finding.tests_passed = finding.tests_performed - confirmed_count
                finding.add_recommendation(
                    1, "Never render user input through the template engine",
                    "Server-Side Template Injection allows arbitrary code execution on the server in most "
                    "template engines (Jinja2, Twig, Freemarker, Velocity...).",
                    "Treat all user input as data, never as template source. Use a sandboxed/logic-less "
                    "template mode if user-controlled templates are unavoidable.",
                    ["OWASP: Server-Side Template Injection", "PortSwigger: SSTI"],
                )
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No SSTI detected across {len(test_targets)} parameter(s) and "
                        f"{len(self.ENGINE_PAYLOADS)} template engine syntaxes",
                        payload=None,
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error scanning SSTI: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
