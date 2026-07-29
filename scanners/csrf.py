import re
import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.CSRF')

class CSRFScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "CSRF Protection"

        self.csrf_patterns = [
            r'csrf',
            r'_token',
            r'csrf_token',
            r'csrfmiddlewaretoken',
            r'__RequestVerificationToken',
            r'csrf\-param',
            r'CSRFName',
            r'csrf_test_name',
            r'YII_CSRF_TOKEN',
            r'CRAFT_CSRF_TOKEN',
        ]

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            resp = self.session.get(self.target, timeout=10)
            content = resp.text

            found = False
            found_patterns = []
            for pattern in self.csrf_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found = True
                    found_patterns.append(pattern)
                    if not found:
                        finding.add_evidence(
                            self._evidence_builder.verified(
                                f"CSRF token pattern detected: {pattern}",
                                payload=None
                            )
                        )
                    break

            finding.tests_performed = len(self.csrf_patterns)
            finding.tests_run = finding.tests_performed

            if found:
                if len(found_patterns) > 1:
                    finding.confidence = min(100, finding.confidence + 5)
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            else:
                has_forms = bool(re.search(r'<form[^>]*action=[^>]*>', content, re.IGNORECASE))
                has_post_forms = bool(re.search(r'<form[^>]*method=["\']post["\']', content, re.IGNORECASE))

                if has_post_forms:
                    finding.add_evidence(
                        self._evidence_builder.confirmed(
                            "POST forms present but no CSRF tokens detected",
                            payload=None
                        )
                    )
                    finding.severity = Severity.MEDIUM
                elif has_forms:
                    finding.add_evidence(
                        self._evidence_builder.likely(
                            "Forms present but no CSRF tokens detected",
                            payload=None
                        )
                    )
                    finding.severity = Severity.LOW
                else:
                    finding.add_evidence(
                        self._evidence_builder.possible(
                            "No CSRF tokens detected (no forms found either)",
                            payload=None
                        )
                    )
                    finding.severity = Severity.LOW

                finding.status = Status.WARNING
                finding.tests_passed = 0
                finding.add_recommendation(
                    1, "Implement CSRF tokens for all state-changing requests",
                    "Without CSRF protection, attackers can trick users into performing unwanted actions.",
                    "Use anti-CSRF tokens (e.g., synchronizer tokens) in all forms and AJAX requests.",
                    ["OWASP: CSRF", "Mozilla: CSRF Prevention"]
                )

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error scanning CSRF: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
