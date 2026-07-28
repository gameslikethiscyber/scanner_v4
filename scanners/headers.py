"""
Headers Scanner - v3.3 (يدعم POST)
"""

import re
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

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
            
            required_headers = {
                'Content-Security-Policy': {
                    'desc': 'Primary XSS defense',
                    'recommendation': "default-src 'self'; script-src 'self'; style-src 'self'",
                    'why': 'CSP prevents XSS and data injection attacks.',
                    'how': 'Add the Content-Security-Policy header with appropriate directives.',
                    'refs': ['OWASP: CSP', 'Mozilla: CSP']
                },
                'X-Frame-Options': {
                    'desc': 'Clickjacking protection',
                    'recommendation': 'DENY or SAMEORIGIN',
                    'why': 'Prevents your site from being embedded in frames.',
                    'how': 'Add X-Frame-Options: DENY or SAMEORIGIN.',
                    'refs': ['OWASP: Clickjacking', 'Mozilla: X-Frame-Options']
                },
                'X-Content-Type-Options': {
                    'desc': 'MIME sniffing protection',
                    'recommendation': 'nosniff',
                    'why': 'Prevents browsers from MIME-sniffing responses.',
                    'how': 'Add X-Content-Type-Options: nosniff.',
                    'refs': ['Mozilla: X-Content-Type-Options']
                },
                'Strict-Transport-Security': {
                    'desc': 'HTTPS enforcement',
                    'recommendation': 'max-age=31536000; includeSubDomains',
                    'why': 'Enforces HTTPS connections, preventing SSL stripping.',
                    'how': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains.',
                    'refs': ['OWASP: HSTS', 'Mozilla: HSTS']
                },
                'Referrer-Policy': {
                    'desc': 'Referrer control',
                    'recommendation': 'strict-origin-when-cross-origin',
                    'why': 'Controls referrer information, protecting user privacy.',
                    'how': 'Add Referrer-Policy: strict-origin-when-cross-origin.',
                    'refs': ['Mozilla: Referrer-Policy']
                }
            }
            
            for header, info in required_headers.items():
                if header in headers:
                    value = headers[header]
                    if header == 'Content-Security-Policy':
                        if 'default-src' not in value and 'script-src' not in value:
                            finding.add_evidence(
                                self._evidence_builder.likely(
                                    f"CSP missing default-src/script-src: {value[:50]}",
                                    payload=value
                                )
                            )
                            finding.add_recommendation(1, "Fix CSP: Add default-src or script-src", info['why'], f"Add default-src 'self' or script-src 'self': {info['recommendation']}", info['refs'])
                        elif 'unsafe-inline' in value:
                            finding.add_evidence(
                                self._evidence_builder.possible(
                                    f"CSP contains unsafe-inline (weakens XSS protection)",
                                    payload=value
                                )
                            )
                            finding.add_recommendation(2, "Remove unsafe-inline from CSP", "unsafe-inline allows inline scripts, reducing CSP's effectiveness against XSS.", "Use nonce or hash-based CSP instead of unsafe-inline.", info['refs'])
                        else:
                            finding.add_evidence(
                                self._evidence_builder.verified(
                                    f"CSP properly configured: {value[:50]}",
                                    payload=value
                                )
                            )
                    elif header == 'Strict-Transport-Security':
                        match = re.search(r'max-age=(\d+)', value)
                        if match and int(match.group(1)) < 31536000:
                            finding.add_evidence(
                                self._evidence_builder.likely(
                                    f"HSTS max-age is low: {match.group(1)}",
                                    payload=value
                                )
                            )
                            finding.add_recommendation(3, "Increase HSTS max-age", "Low max-age reduces HSTS effectiveness.", f"Set max-age to at least 31536000 (1 year): {info['recommendation']}", info['refs'])
                        else:
                            finding.add_evidence(
                                self._evidence_builder.verified(
                                    f"HSTS properly configured",
                                    payload=value
                                )
                            )
                    else:
                        finding.add_evidence(
                            self._evidence_builder.verified(
                                f"{header} is present: {value[:50]}",
                                payload=value
                            )
                        )
                else:
                    finding.add_evidence(
                        self._evidence_builder.likely(
                            f"{header} is missing: {info['desc']}",
                            payload=None
                        )
                    )
                    finding.add_recommendation(4, f"Add {header} header", info['why'], f"Add header: {header}: {info['recommendation']}", info['refs'])
            
            finding.tests_performed = len(required_headers)
            finding.tests_run = finding.tests_performed
            
            missing_count = len([e for e in finding.evidence if 'missing' in getattr(e, 'description', '').lower()])
            if missing_count == 0:
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            else:
                finding.status = Status.WARNING
                finding.tests_passed = finding.tests_performed - missing_count
                finding.severity = Severity.MEDIUM if missing_count >= 3 else Severity.LOW
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error fetching headers: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding