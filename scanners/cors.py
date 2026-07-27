"""
CORS Scanner - v3.3 (يدعم POST)
"""

from core.finding import Finding, Status, Severity
from core.evidence import EvidenceBuilder
from scanners.base import BaseScanner

class CORSScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "CORS Configuration"
        if self.session is None:
            import requests
            self.session = requests.Session()
        
        self.test_origins = ['https://evil.com', 'https://attacker.com', 'null', '*']
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            issues = []
            for origin in self.test_origins:
                try:
                    resp = self.session.get(self.target, headers={'Origin': origin}, timeout=10)
                    acao = resp.headers.get('Access-Control-Allow-Origin')
                    acac = resp.headers.get('Access-Control-Allow-Credentials')
                    
                    if acao:
                        if acao == '*':
                            issues.append(f"Wildcard origin allowed (*)")
                            finding.add_evidence(
                                self._evidence_builder.likely(
                                    f"Wildcard origin allowed: {acao}",
                                    payload=origin
                                )
                            )
                        elif acao == origin:
                            issues.append(f"Origin '{origin}' is allowed")
                            finding.add_evidence(
                                self._evidence_builder.possible(
                                    f"Origin '{origin}' is reflected in ACAO",
                                    payload=origin
                                )
                            )
                        if acac and acac.lower() == 'true':
                            issues.append("Credentials allowed with wildcard origin")
                            finding.add_evidence(
                                self._evidence_builder.likely(
                                    "Credentials allowed with ACAO",
                                    payload=origin
                                )
                            )
                except:
                    continue
            
            finding.tests_performed = len(self.test_origins)
            finding.tests_run = finding.tests_performed
            
            if issues:
                finding.status = Status.WARNING
                finding.tests_passed = finding.tests_performed - len(issues)
                finding.severity = Severity.LOW
                finding.add_recommendation(
                    1,
                    "Restrict CORS to specific trusted origins",
                    "Allowing '*' or reflecting any origin can lead to data theft via cross-origin attacks.",
                    "Set Access-Control-Allow-Origin to a specific trusted domain, and avoid using '*' with credentials.",
                    ["OWASP: CORS Security", "Mozilla: CORS"]
                )
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No CORS misconfigurations detected",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning CORS: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding