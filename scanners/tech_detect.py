"""
Technology Detection Scanner - v3.3 (يدعم POST)
"""

import re
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

class TechDetectScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Technology Detection"
        
        self.tech_patterns = {
            'WordPress': [r'wp-content', r'wp-includes'],
            'Drupal': [r'drupal', r'Drupal'],
            'Laravel': [r'laravel', r'X-Powered-By.*Laravel'],
            'React': [r'react', r'reactjs'],
            'Angular': [r'angular', r'ng-'],
            'Vue': [r'vue', r'vuejs'],
            'Next.js': [r'next.js', r'__NEXT_DATA__'],
            'Express': [r'express', r'X-Powered-By.*Express']
        }
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            resp = self.session.get(self.target, timeout=10)
            detected = []
            
            for tech, patterns in self.tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        detected.append(tech)
                        break
            
            finding.tests_performed = len(self.tech_patterns)
            finding.tests_run = finding.tests_performed
            
            if detected:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"Technologies detected: {', '.join(detected)}",
                        payload=None
                    )
                )
                finding.fingerprint['detected_technologies'] = detected
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No specific technologies detected",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error detecting technologies: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding