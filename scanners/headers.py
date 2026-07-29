import re
import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner
from core.response_analyzer import ResponseAnalyzer

logger = logging.getLogger('SeaScanner.Headers')

class HeadersScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Headers Security"

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            resp = self.session.get(self.target, timeout=15, allow_redirects=True)
            headers = resp.headers

            analysis = ResponseAnalyzer.analyze_response(resp)

            for sec_hdr in analysis.security_headers:
                if sec_hdr.present:
                    if sec_hdr.valid:
                        finding.add_evidence(
                            self._evidence_builder.verified(
                                f"{sec_hdr.name}: {sec_hdr.value[:60]}",
                                payload=sec_hdr.value,
                            )
                        )
                    else:
                        finding.add_evidence(
                            self._evidence_builder.likely(
                                f"{sec_hdr.name} misconfigured: {sec_hdr.recommendation}",
                                payload=sec_hdr.value,
                            )
                        )
                        finding.add_recommendation(
                            2, f"Fix {sec_hdr.name}", sec_hdr.recommendation,
                            f"Configure {sec_hdr.name} properly", []
                        )
                else:
                    finding.add_evidence(
                        self._evidence_builder.likely(
                            f"{sec_hdr.name} is missing: {sec_hdr.recommendation[:60]}",
                            payload=None,
                        )
                    )
                    finding.add_recommendation(
                        4, f"Add {sec_hdr.name} header",
                        f"Security header {sec_hdr.name} is missing",
                        f"Add header: {sec_hdr.name}", []
                    )

            csp_value = headers.get('Content-Security-Policy', '')
            if csp_value:
                if 'unsafe-inline' in csp_value and 'nonce' not in csp_value:
                    finding.add_evidence(
                        self._evidence_builder.possible(
                            "CSP uses unsafe-inline without nonce (weakens XSS protection)",
                            payload=csp_value[:80],
                        )
                    )

            hsts_value = headers.get('Strict-Transport-Security', '')
            if hsts_value:
                match = re.search(r'max-age=(\d+)', hsts_value)
                if match and int(match.group(1)) < 31536000:
                    finding.add_evidence(
                        self._evidence_builder.likely(
                            f"HSTS max-age is low ({match.group(1)}s, minimum 31536000s)",
                            payload=hsts_value,
                        )
                    )

            finding.tests_performed = len(analysis.security_headers)
            finding.tests_run = finding.tests_performed

            from core.evidence import EvidenceLevel
            missing_or_invalid = len([e for e in finding.evidence if getattr(e, 'level', None) in (
                EvidenceLevel.LIKELY, EvidenceLevel.POSSIBLE, EvidenceLevel.UNKNOWN
            )])
            if missing_or_invalid == 0:
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            else:
                finding.status = Status.WARNING
                finding.tests_passed = finding.tests_performed - missing_or_invalid
                finding.severity = Severity.MEDIUM if missing_or_invalid >= 3 else Severity.LOW

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error fetching headers: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
