"""
HTTP Methods Scanner - v3.3 (يدعم POST)
"""

from core.finding import Finding, Status, Severity
from core.evidence import EvidenceBuilder
from scanners.base import BaseScanner

class HTTPMethodsScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "HTTP Methods"
        if self.session is None:
            import requests
            self.session = requests.Session()
        
        self.methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT', 'PATCH']
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            allowed = []
            for method in self.methods:
                try:
                    resp = self.session.request(method, self.target, timeout=10)
                    if resp.status_code not in [405, 501, 403]:
                        allowed.append(method)
                except:
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
            
            dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
            dangerous_found = [m for m in allowed if m in dangerous]
            
            if dangerous_found:
                finding.add_evidence(
                    self._evidence_builder.likely(
                        f"Dangerous methods allowed: {', '.join(dangerous_found)}",
                        payload=None
                    )
                )
                finding.status = Status.WARNING
                finding.tests_passed = finding.tests_performed - len(dangerous_found)
                finding.severity = Severity.MEDIUM
            else:
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning HTTP methods: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding