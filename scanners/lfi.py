import re
import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.LFI')

class LFIScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "LFI Detection"

        depth = self._guess_depth()
        traversal = '../' * depth

        self.primary_payloads = [
            f'{traversal}etc/passwd',
            f'{traversal}boot.ini',
            f'..\\..\\..\\..\\windows\\win.ini',
            f'{traversal}etc/passwd%00',
            f'{traversal}etc/passwd%2500',
            f'{traversal}proc/self/environ',
        ]
        self.confirm_payloads = [
            f'../../../etc/passwd',
            f'..\\..\\..\\..\\windows\\win.ini',
            f'{traversal}etc/hosts',
        ]
        self.cross_payloads = [
            f'{traversal}etc/issue',
            f'..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        ]
        self.lfi_patterns = ['root:x:', '[extensions]', 'for 16-bit app support', 'bin:/', 'daemon:']
        self.lfi_error_patterns = [
            'failed to open stream: No such file',
            'file_get_contents',
            'include_once',
            'require_once',
            'include(',
            'require(',
            'Warning: include',
            'Warning: require',
            'Fatal error: require_once',
            'failed to open stream: Permission denied',
            'No such file or directory',
            'File not found',
        ]

    def _guess_depth(self):
        path = self.target.split('://', 1)[-1]
        path = path.split('?')[0].split('#')[0]
        depth = path.count('/')
        return max(3, min(depth + 1, 8))

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
                if self._check_lfi(finding, param):
                    break

            finding.tests_performed = len(self.primary_payloads) * len(params)
            finding.tests_run = finding.tests_performed

            if finding.confirmations > 0:
                finding.status = Status.FAIL
                finding.tests_passed = finding.confirmations
                finding.severity = Severity.HIGH
                if finding.confirmations >= 2:
                    finding.cross_validated = True
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

    def _check_lfi(self, finding, param):
        for payload in self.primary_payloads:
            try:
                test_url = self.inject_payload(param, payload)
                resp = self.session.get(test_url, timeout=10)

                for pattern in self.lfi_patterns:
                    if pattern in resp.text:
                        for confirm_path in self.confirm_payloads:
                            confirm_url = self.inject_payload(param, confirm_path)
                            confirm_resp = self.session.get(confirm_url, timeout=10)
                            if pattern in confirm_resp.text:
                                for cross_path in self.cross_payloads:
                                    try:
                                        cross_url = self.inject_payload(param, cross_path)
                                        cross_resp = self.session.get(cross_url, timeout=10)
                                        if pattern in cross_resp.text or any(p in cross_resp.text for p in self.lfi_patterns):
                                            self.capture_http_evidence(
                                                finding,
                                                f"LFI vulnerability confirmed in '{param}' (triple-verified)",
                                                resp, payload=payload, parameter=param,
                                            )
                                            finding.confirmations += 2
                                            return True
                                    except Exception:
                                        pass
                                self.capture_http_evidence(
                                    finding,
                                    f"LFI vulnerability in '{param} (multi-confirmed)",
                                    resp, payload=payload, parameter=param,
                                )
                                finding.confirmations += 1
                                return True
                        finding.add_evidence(
                            self._evidence_builder.likely(
                                f"Possible LFI in '{param}' (content match but confirmation unclear)",
                                payload=payload, parameter=param
                            )
                        )
                        finding.confirmations += 1
                        return True

                if finding.confirmations == 0:
                    for pattern in self.lfi_error_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            finding.add_evidence(
                                self._evidence_builder.possible(
                                    f"Possible LFI via error in '{param}': {pattern}",
                                    payload=payload, parameter=param
                                )
                            )
                            finding.confirmations += 1
                            return True
            except Exception:
                continue
        return False
