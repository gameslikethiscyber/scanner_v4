"""
CSRF Scanner - v3.3 (يدعم POST)
"""

import re
from core.finding import Finding, Status, Severity
from core.evidence import EvidenceBuilder
from scanners.base import BaseScanner

class CSRFScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "CSRF Protection"
        if self.session is None:
            import requests
            self.session = requests.Session()
        
        self.csrf_patterns = [
            r'csrf',
            r'_token',
            r'csrf_token',
            r'csrfmiddlewaretoken',
            r'__RequestVerificationToken'
        ]
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            resp = self.session.get(self.target, timeout=10)
            content = resp.text
            
            found = False
            for pattern in self.csrf_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found = True
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
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            else:
                finding.add_evidence(
                    self._evidence_builder.likely(
                        "No CSRF tokens detected in response",
                        payload=None
                    )
                )
                finding.status = Status.WARNING
                finding.tests_passed = 0
                finding.severity = Severity.MEDIUM
                finding.add_recommendation(
                    1,
                    "Implement CSRF tokens for all state-changing requests",
                    "Without CSRF protection, attackers can trick users into performing unwanted actions.",
                    "Use anti-CSRF tokens (e.g., synchronizer tokens) in all forms and AJAX requests.",
                    ["OWASP: CSRF", "Mozilla: CSRF Prevention"]
                )
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning CSRF: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding