"""
XSS Scanner - v3.3 (POST + Contexts)
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.finding import Finding, Status, Severity
from core.evidence import EvidenceBuilder
from scanners.base import BaseScanner

class XSSScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "XSS Detection"
        if self.session is None:
            import requests
            self.session = requests.Session()
        
        self.contexts = {
            'html': {
                'payloads': ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
                'patterns': [r'<script>.*?alert', r'onerror=.*?alert']
            },
            'attribute': {
                'payloads': ['" onmouseover=alert("XSS") "', "' onfocus=alert('XSS') '"],
                'patterns': [r'onmouseover=.*?alert', r'onfocus=.*?alert']
            },
            'javascript': {
                'payloads': ["';alert('XSS');//", '";alert("XSS");//'],
                'patterns': [r';alert.*?;', r'";alert.*?;']
            },
            'url': {
                'payloads': ["javascript:alert('XSS')", "javascript:alert('XSS')//"],
                'patterns': [r'javascript:.*?alert']
            },
            'svg': {
                'payloads': ["<svg><script>alert('XSS')</script>", "<svg/onload=alert('XSS')>"],
                'patterns': [r'<svg>.*?<script>.*?alert', r'<svg/onload=.*?alert']
            }
        }
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            params = self.get_params()
            post_params = self.post_data
            has_params = bool(params or post_params)
            
            if not has_params:
                finding.status = Status.SKIPPED
                finding.skip_reason = "No URL parameters or POST data found to test for XSS"
                return finding
            
            confirmations = 0
            evidence_list = []
            total_payloads = 0
            
            if params:
                for context_name, context_data in self.contexts.items():
                    for param in params:
                        for payload in context_data['payloads']:
                            total_payloads += 1
                            try:
                                test_url = self.inject_payload(param, payload)
                                resp = self.session.get(test_url, timeout=10)
                                for pattern in context_data['patterns']:
                                    if re.search(pattern, resp.text, re.IGNORECASE):
                                        evidence_list.append(f"XSS ({context_name}) in GET param '{param}'")
                                        confirmations += 1
                                        break
                                if confirmations > 0:
                                    break
                            except:
                                continue
                        if confirmations > 0:
                            break
            
            if post_params and confirmations == 0:
                post_keys = list(post_params.keys())
                for context_name, context_data in self.contexts.items():
                    for param in post_keys:
                        for payload in context_data['payloads']:
                            total_payloads += 1
                            try:
                                data = self.post_data.copy()
                                data[param] = payload
                                resp = self.session.post(self.target, data=data, timeout=10)
                                for pattern in context_data['patterns']:
                                    if re.search(pattern, resp.text, re.IGNORECASE):
                                        evidence_list.append(f"XSS ({context_name}) in POST param '{param}'")
                                        confirmations += 1
                                        break
                                if confirmations > 0:
                                    break
                            except:
                                continue
                        if confirmations > 0:
                            break
            
            finding.tests_performed = total_payloads
            finding.tests_run = total_payloads
            
            if confirmations > 0:
                for ev in evidence_list:
                    finding.add_evidence(
                        self._evidence_builder.confirmed(ev, payload=None)
                    )
                finding.confirmations = confirmations
                finding.status = Status.FAIL
                finding.tests_passed = confirmations
                finding.severity = Severity.HIGH
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No XSS detected. Tested {total_payloads} payloads.",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = total_payloads
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error during XSS scan: {str(e)}", payload=None)
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