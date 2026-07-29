import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.OpenRedirect')

class OpenRedirectScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Open Redirect"

        self.primary_payloads = [
            'https://evil.com',
            'http://attacker.com',
            '//evil.com',
            '//google.com',
            'https://evil.com/redirect',
            '//evil.com%2f@',
        ]
        self.confirm_payloads = [
            'https://attacker.net',
            '//attacker.com',
            'https://evil.com/test',
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
                for payload in self.primary_payloads:
                    try:
                        test_url = self.inject_payload(param, payload)
                        resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                        if resp.status_code in [301, 302, 303, 307, 308]:
                            location = resp.headers.get('Location', '')
                            if payload in location or payload.replace('//', '') in location:
                                for confirm_payload in self.confirm_payloads:
                                    try:
                                        confirm_url = self.inject_payload(param, confirm_payload)
                                        confirm_resp = self.session.get(confirm_url, timeout=10, allow_redirects=False)
                                        if confirm_resp.status_code in [301, 302, 303, 307, 308]:
                                            confirm_loc = confirm_resp.headers.get('Location', '')
                                            if confirm_payload in confirm_loc or confirm_payload.replace('//', '') in confirm_loc:
                                                self.capture_http_evidence(
                                                    finding,
                                                    f"Open redirect confirmed in '{param}' (multi-verified)",
                                                    resp, payload=payload, parameter=param,
                                                )
                                                finding.confirmations += 2
                                                finding.cross_validated = True
                                                break
                                    except Exception:
                                        continue
                                if finding.confirmations == 0:
                                    self.capture_http_evidence(
                                        finding,
                                        f"Open redirect in '{param}'",
                                        resp, payload=payload, parameter=param,
                                    )
                                    finding.confirmations += 1
                                break
                    except Exception:
                        continue
                if finding.confirmations > 0:
                    break

            finding.tests_performed = len(self.primary_payloads) * len(params)
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
                self._evidence_builder.error(f"Error scanning Open Redirect: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
