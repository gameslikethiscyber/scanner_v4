"""
DNS Scanner - v3.3 (يدعم POST)
"""

import dns.resolver
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

class DNSScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "DNS Security"
        self.record_types = ['A', 'MX', 'TXT', 'NS', 'CNAME']
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            domain = self.target.replace('https://', '').replace('http://', '').split('/')[0]
            found = []
            
            for record in self.record_types:
                try:
                    dns.resolver.resolve(domain, record)
                    found.append(record)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                    continue
            
            finding.tests_performed = len(self.record_types)
            finding.tests_run = finding.tests_performed
            
            if found:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"DNS records found: {', '.join(found)}",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = len(found)
            else:
                finding.add_evidence(
                    self._evidence_builder.likely(
                        "No DNS records found for domain",
                        payload=None
                    )
                )
                finding.status = Status.WARNING
                finding.tests_passed = 0
                finding.severity = Severity.LOW
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning DNS: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding