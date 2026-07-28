"""
Cookies Scanner - v3.3 (يدعم POST)
"""

from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

class CookiesScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Cookies Security"
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            resp = self.session.get(self.target, timeout=10, allow_redirects=True)
            cookies = resp.cookies
            
            if not cookies:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No cookies found to analyze",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_performed = 0
                return finding
            
            issues = []
            for cookie in cookies:
                if not cookie.secure:
                    issues.append(f"Cookie '{cookie.name}' missing Secure flag")
                cookie_rest = {k.lower(): v for k, v in (getattr(cookie, '_rest', {}) or {}).items()}
                has_httponly = 'httponly' in cookie_rest
                if not has_httponly:
                    issues.append(f"Cookie '{cookie.name}' missing HttpOnly flag")
                has_samesite = 'samesite' in cookie_rest
                if not has_samesite:
                    issues.append(f"Cookie '{cookie.name}' missing SameSite flag")
            
            finding.tests_performed = len(cookies)
            finding.tests_run = finding.tests_performed
            
            if issues:
                for issue in issues:
                    finding.add_evidence(
                        self._evidence_builder.likely(
                            issue,
                            payload=None
                        )
                    )
                finding.status = Status.WARNING
                finding.tests_passed = finding.tests_performed - len(issues)
                finding.severity = Severity.MEDIUM if len(issues) >= 3 else Severity.LOW
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"All {len(cookies)} cookies have proper security flags",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed
            
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.unknown(
                    f"Error scanning cookies: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding