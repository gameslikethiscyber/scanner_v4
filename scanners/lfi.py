import re
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

class LFIScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "LFI Detection"

        depth = self._guess_depth()
        traversal = '../' * depth

        self.payloads = [
            f'{traversal}etc/passwd',
            f'{traversal}boot.ini',
            f'..\\..\\..\\..\\windows\\win.ini',
            f'{traversal}etc/passwd%00',
        ]
        self.lfi_patterns = ['root:x:', '[extensions]', 'for 16-bit app support']
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
                for payload in self.payloads:
                    try:
                        test_url = self.inject_payload(param, payload)
                        resp = self.session.get(test_url, timeout=10)

                        for pattern in self.lfi_patterns:
                            if pattern in resp.text:
                                confirm_path = f'../../../etc/passwd' if '../' in payload else f'..\\..\\..\\..\\windows\\win.ini'
                                confirm_url = self.inject_payload(param, confirm_path)
                                confirm_resp = self.session.get(confirm_url, timeout=10)
                                if pattern in confirm_resp.text:
                                    finding.add_evidence(
                                        self._evidence_builder.confirmed(
                                            f"LFI vulnerability in parameter '{param}' (multi-confirmed)",
                                            payload=payload,
                                            parameter=param
                                        )
                                    )
                                    finding.confirmations += 1
                                else:
                                    finding.add_evidence(
                                        self._evidence_builder.likely(
                                            f"Possible LFI in parameter '{param}'",
                                            payload=payload,
                                            parameter=param
                                        )
                                    )
                                    finding.confirmations += 1
                                break

                        if finding.confirmations == 0:
                            for pattern in self.lfi_error_patterns:
                                if re.search(pattern, resp.text, re.IGNORECASE):
                                    finding.add_evidence(
                                        self._evidence_builder.possible(
                                            f"Possible LFI via error in parameter '{param}': {pattern}",
                                            payload=payload,
                                            parameter=param
                                        )
                                    )
                                    finding.confirmations += 1
                                    break

                        if finding.confirmations > 0:
                            break
                    except Exception:
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
