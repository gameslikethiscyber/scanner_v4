"""
Open Redirect Scanner - v3.3 (يدعم POST)
"""

from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

class OpenRedirectScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Open Redirect"
        
        self.payloads = [
            'https://evil.com',
            'http://attacker.com',
            '//evil.com',
            '//google.com'
        ]
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            params = self.get_params()
            if not params:
                finding.status = Status.SKIPPED
                finding.skip_reason = "No URL parameters found to test for Open Redirect"
                return finding
            
            for param in params:
                for payload in self.payloads:
                    try:
                        test_url = self.inject_payload(param, payload)
                        resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                        if resp.status_code in [301, 302, 303, 307, 308]:
                            location = resp.headers.get('Location', '')
                            if payload in location or payload.replace('//', '') in location:
                                finding.add_evidence(
                                    self._evidence_builder.confirmed(
                                        f"Open redirect in parameter '{param}'",
                                        payload=payload,
                                        parameter=param
                                    )
                                )
                                finding.confirmations += 1
                                break
                    except Exception:
                        continue
            
            finding.tests_performed = len(self.payloads) * len(params)
            finding.tests_run = finding.tests_performed
            
            if finding.confirmations > 0:
                finding.status = Status.FAIL
                finding.tests_passed = finding.confirmations
                finding.severity = Severity.MEDIUM
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No open redirect detected. Tested {finding.tests_performed} payloads.",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning Open Redirect: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding