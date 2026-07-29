import re
import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner
from core.response_analyzer import ResponseAnalyzer

logger = logging.getLogger('SeaScanner.SourceLeaks')

class SourceLeaksScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Source Code Leaks"

        self.patterns = [
            'DB_PASSWORD\\s*=',
            'API_KEY\\s*=',
            'SECRET_KEY\\s*=',
            "password\\s*=\\s*['\"][^'\"]+['\"]",
            'PRIVATE_KEY',
            '-----BEGIN.*PRIVATE KEY-----',
            'access_key\\s*=',
            'secret_access_key\\s*=',
            '\\.git/config',
            '\\.git/HEAD',
            'stack trace:',
            'Traceback \\(most recent call last\\)',
            'Warning:.*\\.php.*on line',
            'Fatal error:.*in .*\\.php',
        ]

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            resp = self.session.get(self.target, timeout=10)
            content = resp.text

            found = []
            for pattern in self.patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found.append(pattern)

            sensitive = ResponseAnalyzer.extract_sensitive_patterns(content)
            if sensitive:
                found.extend([f"[{s}]" for s in sensitive])

            finding.tests_performed = len(self.patterns)
            finding.tests_run = finding.tests_performed

            if found:
                self.capture_http_evidence(
                    finding,
                    f"Potential source code patterns found: {', '.join(found[:5])}",
                    resp,
                )
                finding.status = Status.WARNING
                finding.tests_passed = finding.tests_performed - len(found)
                finding.severity = Severity.LOW
                finding.detection_methods = found[:3]
            else:
                finding.add_evidence(
                    self._evidence_builder.verified("No source code leak patterns detected", payload=None)
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error scanning source leaks: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
