import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner
from core.response_analyzer import ResponseAnalyzer

logger = logging.getLogger('SeaScanner.Cookies')

class CookiesScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Cookies Security"

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            resp = self.session.get(self.target, timeout=10, allow_redirects=True)
            analysis = ResponseAnalyzer.analyze_response(resp)
            cookies = analysis.cookies

            if not cookies:
                finding.add_evidence(
                    self._evidence_builder.verified("No cookies found to analyze", payload=None)
                )
                finding.status = Status.PASS
                finding.tests_performed = 0
                return finding

            issues = []
            for ca in cookies:
                for issue in ca.issues:
                    issues.append(f"Cookie '{ca.name}': {issue}")

            finding.tests_performed = len(cookies)
            finding.tests_run = finding.tests_performed

            if issues:
                for issue in issues:
                    finding.add_evidence(self._evidence_builder.likely(issue, payload=None))
                finding.status = Status.WARNING
                finding.tests_passed = finding.tests_performed - len(issues)
                finding.severity = Severity.MEDIUM if len(issues) >= 3 else Severity.LOW
                finding.add_recommendation(
                    1, "Set secure cookie flags",
                    "Cookies missing Secure/HttpOnly/SameSite flags are vulnerable to theft and CSRF",
                    "Set Secure; HttpOnly; SameSite=Lax on all cookies",
                    ["OWASP: Cookie Security", "Mozilla: Set-Cookie"]
                )
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"All {len(cookies)} cookies have proper security flags", payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.unknown(f"Error scanning cookies: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
