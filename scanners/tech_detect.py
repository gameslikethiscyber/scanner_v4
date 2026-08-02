import logging
from core.finding import Finding
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
            fingerprints = ResponseAnalyzer.detect_technology_fingerprints(
                resp.text, resp.headers
            )

            finding.tests_performed = len(ResponseAnalyzer.TECH_PATTERNS)
            finding.tests_run = finding.tests_performed
            finding.tests_passed = finding.tests_performed

            if fingerprints:
                for fp in fingerprints:
                    finding.add_evidence(
                        self._evidence_builder.verified(
                            f"Technology detected: {fp['technology']} "
                            f"(via {fp['source']} {fp['signal']})",
                            payload=fp['signal'],
                            raw_data=fp,
                        )
                    )
                finding.fingerprint['detected_technologies'] = [
                    fp['technology'] for fp in fingerprints
                ]
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No specific technologies detected",
                        payload=None,
                    )
                )
                finding.fingerprint['detected_technologies'] = []

            version_hints = []
            for hdr, val in resp.headers.items():
                hdr_lower = hdr.lower()
                if any(k in hdr_lower for k in ('server', 'x-powered-by', 'x-aspnet')):
                    version_hints.append(f"{hdr}: {val[:80]}")
            finding.fingerprint['version_hints'] = version_hints

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error detecting technologies: {str(e)}", payload=None)
            )
            finding.scan_errors += 1

        return finding
