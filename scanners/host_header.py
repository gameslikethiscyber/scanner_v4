import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.HostHeader')

class HostHeaderScanner(BaseScanner):
    TEST_HOSTS = ('evil.com', 'attacker.net', '127.0.0.1', 'malicious-host.com')

    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Host Header Injection"

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            for test_host in self.TEST_HOSTS:
                resp = self.session.get(self.target, headers={'Host': test_host}, timeout=10)

                evidence_found = None

                if test_host in resp.text:
                    evidence_found = ('confirmed', f"Host header '{test_host}' reflected in response body", test_host)
                    break

                location = resp.headers.get('Location', '')
                if test_host in location:
                    evidence_found = ('confirmed', f"Host header '{test_host}' used in redirect Location: {location}", test_host)
                    break

                url_patterns = [
                    f'http://{test_host}', f'https://{test_host}',
                    f'//{test_host}', f'src="{test_host}', f'href="{test_host}',
                ]
                for pattern in url_patterns:
                    if pattern in resp.text:
                        evidence_found = ('confirmed', f"Host header '{test_host}' injected into generated URL: {pattern}", test_host)
                        break

                if evidence_found:
                    break

                vary = resp.headers.get('Vary', '')
                if 'Host' not in vary and 'Origin' not in vary:
                    try:
                        baseline = self.session.get(self.target, timeout=10)
                        if baseline.text != resp.text:
                            evidence_found = ('possible', f"Host header '{test_host}' changes response — possible cache poisoning risk", test_host)
                    except Exception:
                        pass

            if evidence_found:
                level, desc, host = evidence_found

                if level == 'confirmed':
                    ev = self._evidence_builder.confirmed(desc, payload=f"Host: {host}")
                    finding.status = Status.FAIL
                    finding.severity = Severity.HIGH
                else:
                    ev = self._evidence_builder.likely(desc, payload=f"Host: {host}")
                    finding.status = Status.WARNING
                    finding.severity = Severity.MEDIUM

                finding.add_evidence(ev)
                finding.tests_performed = len(self.TEST_HOSTS)
                finding.tests_run = len(self.TEST_HOSTS)
                finding.tests_passed = 0
                finding.detection_methods = [level]

                finding.add_recommendation(
                    1, "Validate and whitelist the Host header",
                    "Host header injection can lead to cache poisoning, password reset poisoning, SSRF, and open redirect.",
                    "Configure your web server to only accept requests with valid Host headers matching your domain.",
                    ["OWASP: Host Header Injection", "Mozilla: Host Header Security"]
                )
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "No host header injection detected",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_performed = len(self.TEST_HOSTS)
                finding.tests_run = len(self.TEST_HOSTS)
                finding.tests_passed = len(self.TEST_HOSTS)

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error scanning Host Header: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
