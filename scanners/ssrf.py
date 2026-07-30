import logging
from typing import Optional
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner
from core.oast_manager import OastManager

logger = logging.getLogger('SeaScanner.SSRF')

class SSRFScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None, oast_manager: Optional[OastManager] = None):
        super().__init__(target, session, post_data)
        self.name = "SSRF Detection"
        self.oast_manager = oast_manager

        self.primary_payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost:8080/',
            'http://127.0.0.1/',
            'http://0.0.0.0/',
            'http://[::1]/',
        ]

        self.confirm_payloads = [
            'http://169.254.169.254/',
            'http://127.0.0.2/',
            'http://0.0.0.0/',
            'http://localhost/',
        ]

        self.cross_payloads = [
            'http://127.0.0.1:22/',
            'http://127.0.0.1:3306/',
            'file:///etc/passwd',
        ]

        self.metadata_patterns = [
            'instance-id', 'ami-id', 'public-keys', 'security-credentials',
            'iam', 'local-hostname', 'local-ipv4', 'meta-data',
        ]

        self.ssrf_error_patterns = [
            'Connection refused', 'Connection timed out', 'Name or service not known',
            'Failed to connect', 'NameResolutionFailure', "couldn't connect to host",
            'Connection reset', 'No route to host',
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

            oast_payload_url = None
            if self.oast_manager:
                oast_payload_url = self.oast_manager.generate_payload(
                    0, self.name, "oast"
                )
                if oast_payload_url:
                    self.primary_payloads = list(self.primary_payloads)
                    self.primary_payloads.append(oast_payload_url)

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
                            self.capture_http_evidence(
                                finding,
                                f"SSRF confirmed via metadata service response in '{param}'",
                                resp, payload=payload, parameter=param,
                            )
                            finding.confirmations += 2
                            break

                        if baseline_size > 0:
                            size_diff = abs(content_size - baseline_size)
                            if size_diff > 500:
                                confirm_payload = self.confirm_payloads[i % len(self.confirm_payloads)]
                                try:
                                    if is_post:
                                        confirm_data = self.post_data.copy()
                                        confirm_data[param] = confirm_payload
                                        confirm_resp = self.session.post(self.target, data=confirm_data, timeout=10)
                                    else:
                                        confirm_url = self.inject_payload(param, confirm_payload)
                                        confirm_resp = self.session.get(confirm_url, timeout=10)
                                    confirm_size = abs(len(confirm_resp.text) - baseline_size)
                                    if confirm_size > 300:
                                        cross_payload = self.cross_payloads[i % len(self.cross_payloads)]
                                        try:
                                            if is_post:
                                                cross_data = self.post_data.copy()
                                                cross_data[param] = cross_payload
                                                cross_resp = self.session.post(self.target, data=cross_data, timeout=10)
                                            else:
                                                cross_url = self.inject_payload(param, cross_payload)
                                                cross_resp = self.session.get(cross_url, timeout=10)
                                            cross_size = abs(len(cross_resp.text) - baseline_size)
                                            if cross_size > 200:
                                                self.capture_http_evidence(
                                                    finding,
                                                    f"SSRF confirmed in '{param}' (triple-verified)",
                                                    resp, payload=payload, parameter=param,
                                                )
                                                finding.confirmations += 2
                                                finding.cross_validated = True
                                                break
                                        except Exception:
                                            pass
                                        self.capture_http_evidence(
                                            finding,
                                            f"SSRF confirmed in '{param}' (multi-IP verified)",
                                            resp, payload=payload, parameter=param,
                                        )
                                        finding.confirmations += 1
                                        break
                                except Exception:
                                    finding.add_evidence(
                                        self._evidence_builder.likely(
                                            f"SSRF likely in '{param}' (response size changed by {size_diff} bytes)",
                                            payload=payload, parameter=param,
                                        )
                                    )
                                    finding.confirmations += 1
                                    break

                        if any(pattern in content for pattern in self.ssrf_error_patterns):
                            finding.add_evidence(
                                self._evidence_builder.possible(
                                    f"Possible SSRF in '{param}' (URL fetch error in response)",
                                    payload=payload, parameter=param,
                                )
                            )
                            finding.confirmations += 1
                            break

                    except Exception:
                        continue

                if finding.confirmations > 0:
                    break

            if self.oast_manager and oast_payload_url:
                self.oast_manager.poll()
                if self.oast_manager.check_interaction(oast_payload_url):
                    self.capture_http_evidence(
                        finding,
                        f"SSRF confirmed via OAST interaction for '{param}'",
                        None, payload=oast_payload_url, parameter=param,
                    )
                    finding.confirmations = max(finding.confirmations, 3)
                    finding.cross_validated = True
                    finding.verification_passes = 3

            finding.tests_performed = len(self.primary_payloads) * len(all_params)
            finding.tests_run = finding.tests_performed

            if finding.confirmations > 0:
                finding.status = Status.FAIL
                finding.tests_passed = finding.confirmations
                finding.severity = Severity.HIGH if finding.confirmations >= 2 else Severity.MEDIUM
                finding.detection_methods = ['payload_response', 'multi_ip']
                if finding.cross_validated:
                    finding.verification_passes = 3
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
