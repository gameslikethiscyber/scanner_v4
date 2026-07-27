"""
LFI Scanner - v3.3 (يدعم POST)
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.finding import Finding, Status, Severity
from core.evidence import EvidenceBuilder
from scanners.base import BaseScanner

class LFIScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "LFI Detection"
        if self.session is None:
            import requests
            self.session = requests.Session()
        
        self.payloads = [
            '../../../../etc/passwd',
            '../../../../boot.ini',
            '..\\..\\..\\..\\windows\\win.ini',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        self.patterns = ['root:x:', '[extensions]', 'for 16-bit app support']
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            params = self.get_params()
            if not params:
                finding.status = Status.SKIPPED
                finding.skip_reason = "No URL parameters found to test for LFI"
                return finding
            
            for param in params:
                for payload in self.payloads:
                    try:
                        test_url = self.inject_payload(param, payload)
                        resp = self.session.get(test_url, timeout=10)
                        for pattern in self.patterns:
                            if pattern in resp.text:
                                finding.add_evidence(
                                    self._evidence_builder.confirmed(
                                        f"LFI vulnerability in parameter '{param}'",
                                        payload=payload,
                                        parameter=param
                                    )
                                )
                                finding.confirmations += 1
                                break
                        if finding.confirmations > 0:
                            break
                    except:
                        continue
            
            finding.tests_performed = len(self.payloads) * len(params)
            finding.tests_run = finding.tests_performed
            
            if finding.confirmations > 0:
                finding.status = Status.FAIL
                finding.tests_passed = finding.confirmations
                finding.severity = Severity.HIGH
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No LFI detected. Tested {finding.tests_performed} payloads.",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning LFI: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding
    
    def get_params(self) -> list:
        try:
            parsed = urlparse(self.target)
            return list(parse_qs(parsed.query).keys())
        except:
            return []
    
    def inject_payload(self, param, payload):
        try:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            params[param] = [payload]
            return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        except:
            return self.target