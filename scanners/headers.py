import logging
from core.evidence import EvidenceLevel
from core.finding import Finding
from scanners.base import BaseScanner
from core.response_analyzer import ResponseAnalyzer

logger = logging.getLogger('SeaScanner.Headers')

# Missing-header severity by security impact.
MISSING_SEVERITY = {
    'Content-Security-Policy': 'high',
    'Strict-Transport-Security': 'high',
    'X-Frame-Options': 'medium',
    'X-Content-Type-Options': 'medium',
    'Referrer-Policy': 'medium',
    'Permissions-Policy': 'medium',
    'Cross-Origin-Opener-Policy': 'medium',
    'Cross-Origin-Embedder-Policy': 'low',
    'Cross-Origin-Resource-Policy': 'low',
    'X-XSS-Protection': 'low',
    'Access-Control-Allow-Origin': 'low',
}

CONF_WEIGHTS = {'high': 20, 'medium': 9, 'low': 3}


class HeadersScanner(BaseScanner):

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Headers Security"

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            resp = self.session.get(self.target, timeout=15, allow_redirects=True)
            analysis = ResponseAnalyzer.analyze_response(resp)

            present = []
            missing = []
            issues = []   # {header, issue, severity, name}

            for sec_hdr in analysis.security_headers:
                name = sec_hdr.name
                if sec_hdr.present:
                    present.append(name)
                    if sec_hdr.valid:
                        finding.add_evidence(
                            self._evidence_builder.verified(
                                f"{name}: {sec_hdr.value[:60]}",
                                payload=sec_hdr.value,
                            )
                        )
                    else:
                        severity = sec_hdr.severity or 'medium'
                        issues.append({'header': name, 'issue': 'misconfigured',
                                       'severity': severity})
                        ev = self._evidence_builder.likely(
                            f"{name} misconfigured: {sec_hdr.recommendation}",
                            payload=sec_hdr.value,
                        )
                        ev.raw_data['matched_signal'] = f'{name}_misconfigured'
                        ev.raw_data['severity'] = severity
                        ev.raw_data['reliable_provenance'] = 'ResponseAnalyzer'
                        finding.add_evidence(ev)
                        finding.add_recommendation(
                            2, f"Fix {name}", sec_hdr.recommendation,
                            f"Configure {name} properly", [],
                        )
                else:
                    missing.append(name)
                    severity = MISSING_SEVERITY.get(name, 'medium')
                    issues.append({'header': name, 'issue': 'missing',
                                   'severity': severity})
                    ev = self._evidence_builder.likely(
                        f"{name} is missing: {sec_hdr.recommendation[:60]}",
                        payload=None,
                    )
                    ev.raw_data['matched_signal'] = f'{name}_missing'
                    ev.raw_data['severity'] = severity
                    ev.raw_data['reproducible'] = True
                    finding.add_evidence(ev)
                    finding.add_recommendation(
                        4, f"Add {name} header",
                        f"Security header {name} is missing",
                        f"Add header: {name}", [],
                    )

            finding.tests_performed = len(analysis.security_headers)
            finding.tests_run = finding.tests_performed

            negative = len([e for e in finding.evidence
                            if getattr(e, 'level', None) in (
                                EvidenceLevel.LIKELY,
                                EvidenceLevel.POSSIBLE,
                                EvidenceLevel.UNKNOWN)])
            finding.tests_passed = finding.tests_performed - negative

            # Single-source fingerprint: present/missing lists + unique issues
            # (the analyzer is the sole authority — no duplicated local check).
            finding.fingerprint['header_present'] = sorted(present)
            finding.fingerprint['header_missing'] = sorted(missing)
            finding.fingerprint['header_issues'] = issues
            finding.fingerprint['header_confidence'] = self._confidence(issues)

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error fetching headers: {str(e)}", payload=None)
            )
            finding.scan_errors += 1

        return finding

    @staticmethod
    def _confidence(issues: list) -> int:
        if not issues:
            return 0
        score = sum(CONF_WEIGHTS.get(i['severity'], 3) for i in issues)
        return max(0, min(100, int(score)))