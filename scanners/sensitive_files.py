"""
Sensitive Files Scanner - v3.3 (يدعم POST)
"""

import re
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

class SensitiveFilesScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Sensitive Files"
        
        self.files = {
            '.env': [r'DB_', r'SECRET_', r'APP_KEY', r'PASSWORD', r'API_KEY'],
            'wp-config.php': [r"define\s*\(\s*['\"]DB_", r"define\s*\(\s*['\"]AUTH_KEY"],
            'config.php': [r'\$db_', r'\$config', r'define'],
            'settings.py': [r'SECRET_KEY', r'DATABASES', r'DEBUG'],
            '.git/config': [r'\[remote "origin"\]', r'url = '],
            '.htaccess': [r'RewriteEngine', r'Order allow,deny'],
            '.htpasswd': [r':', r'\$apr1\$'],
            'robots.txt': [r'Disallow:', r'Allow:', r'User-agent:'],
            'sitemap.xml': [r'<urlset', r'<loc>'],
            'composer.json': [r'"require":', r'"name":'],
            'package.json': [r'"dependencies"', r'"scripts"'],
            'README.md': [r'# ', r'## ', r'```'],
            'LICENSE': [r'Copyright', r'MIT License', r'Apache License']
        }
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            exposed_files = []
            for file, patterns in self.files.items():
                try:
                    test_url = self.target.rstrip('/') + '/' + file
                    resp = self.session.get(test_url, timeout=5)
                    
                    if resp.status_code == 200:
                        content = resp.text
                        is_sensitive = False
                        detected_patterns = []
                        
                        for pattern in patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                is_sensitive = True
                                detected_patterns.append(pattern)
                        
                        if is_sensitive:
                            exposed_files.append({
                                'file': file,
                                'patterns': detected_patterns,
                                'url': test_url
                            })
                            finding.add_evidence(
                                self._evidence_builder.confirmed(
                                    f"Sensitive file exposed: {file} (contains: {', '.join(detected_patterns[:2])})",
                                    payload=test_url
                                )
                            )
                        else:
                            finding.add_evidence(
                                self._evidence_builder.verified(
                                    f"File {file} exists but no sensitive content detected",
                                    payload=test_url
                                )
                            )
                except Exception:
                    continue
            
            finding.tests_performed = len(self.files)
            finding.tests_run = finding.tests_performed
            
            if exposed_files:
                finding.status = Status.FAIL
                finding.tests_passed = finding.tests_performed - len(exposed_files)
                finding.severity = Severity.MEDIUM
                for ef in exposed_files[:3]:
                    finding.add_recommendation(
                        1,
                        f"Remove or restrict access to {ef['file']}",
                        f"This file contains sensitive information ({', '.join(ef['patterns'][:2])}) that could be used by attackers.",
                        f"Move {ef['file']} outside the web root, or configure your web server to deny access.",
                        ["OWASP: Sensitive Data Exposure", "Mozilla: Web Security"]
                    )
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No sensitive files exposed. Checked {finding.tests_performed} files.",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning sensitive files: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding