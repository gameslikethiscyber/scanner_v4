"""
Source Leaks Scanner - v3.3 (يدعم POST)
"""

import re
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

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
            
            finding.tests_performed = len(self.patterns)
            finding.tests_run = finding.tests_performed
            
            if found:
                finding.add_evidence(
                    self._evidence_builder.likely(
                        f"Potential source code patterns found: {', '.join(found[:3])}",
                        payload=None
                    )
                )
                finding.status = Status.WARNING
                finding.tests_passed = finding.tests_performed - len(found)
                finding.severity = Severity.LOW
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No source code leak patterns detected",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning source leaks: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding