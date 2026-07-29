import re
import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner
from core.response_analyzer import ResponseAnalyzer

logger = logging.getLogger('SeaScanner.TechDetect')

class TechDetectScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Technology Detection"

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            resp = self.session.get(self.target, timeout=10)

            analysis = ResponseAnalyzer.analyze_response(resp)
            detected = analysis.technologies

            finding.tests_performed = len(ResponseAnalyzer.TECH_PATTERNS)
            finding.tests_run = finding.tests_performed

            if detected:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"Technologies detected: {', '.join(detected)}",
                        payload=None
                    )
                )
                finding.fingerprint['detected_technologies'] = detected
                finding.fingerprint['version_hints'] = []

                for hdr, val in resp.headers.items():
                    hdr_lower = hdr.lower()
                    if 'server' in hdr_lower or 'x-powered-by' in hdr_lower or 'x-aspnet' in hdr_lower:
                        finding.fingerprint['version_hints'].append(f"{hdr}: {val[:80]}")

                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            else:
                finding.add_evidence(
                    self._evidence_builder.verified("No specific technologies detected", payload=None)
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error detecting technologies: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
