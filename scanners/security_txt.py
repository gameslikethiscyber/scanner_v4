"""
Security.txt Scanner - v3.3 (يدعم POST)
"""

from core.finding import Finding, Status, Severity
from core.evidence import EvidenceBuilder
from scanners.base import BaseScanner

class SecurityTxtScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Security.txt"
        if self.session is None:
            import requests
            self.session = requests.Session()
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            base = self.target.rstrip('/')
            resp = self.session.get(f"{base}/.well-known/security.txt", timeout=10)
            
            finding.tests_performed = 1
            finding.tests_run = 1
            
            if resp.status_code == 200:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "Security.txt found",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = 1
            else:
                finding.add_evidence(
                    self._evidence_builder.likely(
                        "Security.txt not found",
                        payload=None
                    )
                )
                finding.status = Status.WARNING
                finding.tests_passed = 0
                finding.severity = Severity.LOW
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning security.txt: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding