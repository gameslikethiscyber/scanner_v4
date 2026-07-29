import requests
import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.HTTPMethods')

class HTTPMethodsScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "HTTP Methods"

        self.methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT', 'PATCH', 'HEAD', 'PURGE']

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            allowed = []
            dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH', 'PURGE']

            for method in self.methods:
                try:
                    resp = self.session.request(method, self.target, timeout=10)
                    if resp.status_code not in [405, 501, 403, 404]:
                        allowed.append(method)
                except requests.RequestException:
                    continue

            finding.tests_performed = len(self.methods)
            finding.tests_run = finding.tests_performed

            if allowed:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"Allowed methods: {', '.join(allowed)}",
                        payload=None
                    )
                )

            dangerous_found = [m for m in allowed if m in dangerous]

            if dangerous_found:
                for method in dangerous_found:
                    self.capture_http_evidence(
                        finding,
                        f"Dangerous {method} method is allowed on the server",
                        resp=None,
                        payload=method,
                        method=method,
                    )
                finding.status = Status.WARNING
                finding.tests_passed = finding.tests_performed - len(dangerous_found)
                finding.severity = Severity.MEDIUM
                finding.detection_methods = dangerous_found
                finding.add_recommendation(
                    1, f"Disable dangerous HTTP methods: {', '.join(dangerous_found)}",
                    "Dangerous HTTP methods can be used to modify or delete resources on the server.",
                    f"Restrict to GET, POST, HEAD only. Disable: {', '.join(dangerous_found)}",
                    ["OWASP: HTTP Methods", "Mozilla: HTTP Methods"]
                )
            else:
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error scanning HTTP methods: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
