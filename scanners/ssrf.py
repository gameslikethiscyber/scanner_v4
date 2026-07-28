from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

class SSRFScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "SSRF Detection"

        self.primary_payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost:8080/',
            'http://127.0.0.1/',
        ]

        self.confirm_payloads = [
            'http://169.254.169.254/',
            'http://127.0.0.2/',
            'http://0.0.0.0/',
        ]

        self.metadata_patterns = [
            'instance-id', 'ami-id', 'public-keys', 'security-credentials',
            'iam', 'local-hostname', 'local-ipv4'
        ]

        self.ssrf_error_patterns = [
            'Connection refused', 'Connection timed out', 'Name or service not known',
            'Failed to connect', 'NameResolutionFailure', "couldn't connect to host"
        ]

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            params = self.get_params()
            post_keys = list(self.post_data.keys()) if self.post_data else []
            has_params = bool(params or post_keys)

            if not has_params:
                finding.status = Status.SKIPPED
                finding.skip_reason = "No URL parameters or POST data found to test for SSRF"
                return finding

            baseline = self._get_baseline()
            baseline_size = len(baseline) if baseline else 0

            all_params = params + post_keys

            for param in all_params:
                is_post = param in post_keys
                for i, payload in enumerate(self.primary_payloads):
                    try:
                        if is_post:
                            data = self.post_data.copy()
                            data[param] = payload
                            resp = self.session.post(self.target, data=data, timeout=10)
                        else:
                            test_url = self.inject_payload(param, payload)
                            resp = self.session.get(test_url, timeout=10)

                        if resp.status_code != 200:
                            continue

                        content = resp.text
                        content_size = len(content)

                        if any(pattern in content for pattern in self.metadata_patterns):
                            finding.add_evidence(
                                self._evidence_builder.confirmed(
                                    f"SSRF confirmed via metadata service response in parameter '{param}'",
                                    payload=payload,
                                    parameter=param
                                )
                            )
                            finding.confirmations += 1
                            break

                        if baseline_size > 0:
                            size_diff = abs(content_size - baseline_size)
                            if size_diff > 500:
                                confirm_payload = self.confirm_payloads[i % len(self.confirm_payloads)]
                                try:
                                    confirm_url = self.inject_payload(param, confirm_payload)
                                    confirm_resp = self.session.get(confirm_url, timeout=10)
                                    confirm_size = abs(len(confirm_resp.text) - baseline_size)
                                    if confirm_size > 300:
                                        finding.add_evidence(
                                            self._evidence_builder.confirmed(
                                                f"SSRF confirmed in parameter '{param}' (multi-IP verified)",
                                                payload=payload,
                                                parameter=param
                                            )
                                        )
                                        finding.confirmations += 1
                                        break
                                except Exception:
                                    finding.add_evidence(
                                        self._evidence_builder.likely(
                                            f"SSRF likely in parameter '{param}' (response size changed by {size_diff} bytes)",
                                            payload=payload,
                                            parameter=param
                                        )
                                    )
                                    finding.confirmations += 1
                                    break

                        if any(pattern in content for pattern in self.ssrf_error_patterns):
                            finding.add_evidence(
                                self._evidence_builder.possible(
                                    f"Possible SSRF in parameter '{param}' (URL fetch error in response)",
                                    payload=payload,
                                    parameter=param
                                )
                            )
                            finding.confirmations += 1
                            break

                    except Exception:
                        continue

                if finding.confirmations > 0:
                    break

            finding.tests_performed = len(self.primary_payloads) * len(all_params)
            finding.tests_run = finding.tests_performed

            if finding.confirmations > 0:
                finding.status = Status.FAIL
                finding.tests_passed = finding.confirmations
                finding.severity = Severity.HIGH if finding.confirmations >= 2 else Severity.MEDIUM
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No SSRF detected. Tested {finding.tests_performed} payloads.",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(
                    f"Error scanning SSRF: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding

    def _get_baseline(self) -> str:
        try:
            resp = self.session.get(self.target, timeout=10)
            return resp.text if resp.status_code == 200 else ""
        except Exception:
            return ""
