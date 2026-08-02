import requests
import logging
from core.finding import Finding
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.HTTPMethods')

# Methods that can mutate state / risk an info-leak / allow abuse.
DANGEROUS_METHODS = ('PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH', 'PURGE')


class HTTPMethodsScanner(BaseScanner):

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "HTTP Methods"
        self.methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE',
                        'CONNECT', 'PATCH', 'HEAD', 'PURGE']

    @staticmethod
    def _is_allowable(status: int) -> bool:
        """Whether a response proves the method is accepted and processed.

        Only a 2xx (executed / acknowledged) or a 401 (auth-gated but
        recognized) counts as an allowance. Redirects (3xx) are NOT an
        allowance, and 403/404/405/5xx mean the method is disabled or the
        request cannot claim the method.
        """
        if 200 <= status < 300:
            return True
        if status == 401:
            return True
        return False

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            allowed = []
            responses = {}

            for method in self.methods:
                try:
                    resp = self.session.request(method, self.target,
                                                timeout=10,
                                                allow_redirects=False)
                    if self._is_allowable(resp.status_code):
                        allowed.append(method)
                        responses[method] = resp
                except requests.RequestException:
                    continue

            finding.tests_performed = len(self.methods)
            finding.tests_run = finding.tests_performed
            finding.fingerprint['allowed_methods'] = sorted(allowed)

            if allowed:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"Allowed methods: {', '.join(sorted(allowed))}",
                        payload=None,
                    )
                )

            dangerous_found = [m for m in allowed if m in DANGEROUS_METHODS]
            finding.fingerprint['dangerous_methods'] = sorted(dangerous_found)
            finding.fingerprint['http_methods_confidence'] = self._confidence(
                allowed, dangerous_found)

            if dangerous_found:
                for method in dangerous_found:
                    resp = responses.get(method)
                    status = resp.status_code if resp else 0
                    level = 'confirmed' if 200 <= status < 300 else 'likely'
                    self._emit_dangerous(finding, method, status, resp)
                finding.tests_passed = finding.tests_performed - len(dangerous_found)
                finding.detection_methods = dangerous_found
                finding.add_recommendation(
                    1,
                    f"Disable dangerous HTTP methods: {', '.join(dangerous_found)}",
                    "Dangerous HTTP methods can be used to modify or delete "
                    "resources, or leak request data.",
                    f"Restrict to GET, POST, HEAD only. Disable: "
                    f"{', '.join(dangerous_found)}",
                    ["OWASP: HTTP Methods", "Mozilla: HTTP Methods"]
                )
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No dangerous HTTP methods are allowed by the server",
                        payload=None,
                    )
                )
                finding.tests_passed = finding.tests_performed

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning HTTP methods: {str(e)}", payload=None)
            )
            finding.scan_errors += 1

        return finding

    def _emit_dangerous(self, finding, method, status, resp):
        description = (
            f"Dangerous {method} method is allowed on the server "
            f"(status {status})"
        )
        if 200 <= status < 300:
            self.capture_http_evidence(finding, description, resp,
                                       payload=method, method=method)
        else:
            ev = self._evidence_builder.likely(
                description, payload=method, method=method)
            ev.raw_data['status'] = status
            ev.raw_data['matched_signal'] = f'{method}_auth_gated'
            ev.raw_data['reproducible'] = True
            finding.add_evidence(ev)

    @staticmethod
    def _confidence(allowed: list, dangerous: list) -> int:
        if not dangerous:
            return 0
        score = 45 + min(len(dangerous), 3) * 15
        return max(0, min(100, score))