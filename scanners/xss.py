import re
import requests
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

class XSSScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "XSS Detection"

        self.contexts = {
            'html': {
                'payloads': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
                'verify_marker': 'xss_verify_12345',
                'verify_payloads': ["<script>alert(2)</script>", "<img src=x onerror=alert(2)>"]
            },
            'attribute': {
                'payloads': ['" onfocus=alert(1) "', "' onfocus=alert(1) '"],
                'verify_marker': 'xss_verify_12345',
                'verify_payloads': ['" onfocus=alert(2) "', "' onfocus=alert(2) '"]
            },
            'javascript': {
                'payloads': ["';alert(1);//", '";alert(1);//'],
                'verify_marker': 'xss_verify_12345',
                'verify_payloads': ["';alert(2);//", '";alert(2);//']
            }
        }

    def _payload_reflected(self, resp_text, payload):
        escaped_payload = re.escape(payload[:20])
        return bool(re.search(escaped_payload, resp_text, re.IGNORECASE))

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            params = self.get_params()
            post_params = self.post_data
            has_params = bool(params or post_params)

            if not has_params:
                finding.status = Status.SKIPPED
                finding.skip_reason = "No URL parameters or POST data found to test for XSS"
                return finding

            confirmations = 0
            evidence_list = []
            total_payloads = 0

            if params:
                for context_name in self.contexts:
                    ctx = self.contexts[context_name]
                    for param in params:
                        for payload in ctx['payloads']:
                            total_payloads += 1
                            try:
                                test_url = self.inject_payload(param, payload)
                                resp = self.session.get(test_url, timeout=10)
                                if not self._payload_reflected(resp.text, payload):
                                    continue
                                for pattern in [r'<script>.*?alert', r'onerror=.*?alert', r'onfocus=.*?alert', r';alert']:
                                    if re.search(pattern, resp.text, re.IGNORECASE):
                                        verify_payload = ctx['verify_payloads'][0]
                                        verify_url = self.inject_payload(param, verify_payload)
                                        verify_resp = self.session.get(verify_url, timeout=10)
                                        if self._payload_reflected(verify_resp.text, verify_payload):
                                            evidence_list.append(f"XSS ({context_name}) in GET param '{param}'")
                                            confirmations += 1
                                            break
                                if confirmations > 0:
                                    break
                            except requests.RequestException:
                                continue
                        if confirmations > 0:
                            break
                    if confirmations > 0:
                        break

            if post_params and confirmations == 0:
                post_keys = list(post_params.keys())
                for context_name in self.contexts:
                    ctx = self.contexts[context_name]
                    for param in post_keys:
                        for payload in ctx['payloads']:
                            total_payloads += 1
                            try:
                                data = self.post_data.copy()
                                data[param] = payload
                                resp = self.session.post(self.target, data=data, timeout=10)
                                if not self._payload_reflected(resp.text, payload):
                                    continue
                                for pattern in [r'<script>.*?alert', r'onerror=.*?alert', r'onfocus=.*?alert', r';alert']:
                                    if re.search(pattern, resp.text, re.IGNORECASE):
                                        verify_payload = ctx['verify_payloads'][0]
                                        verify_data = self.post_data.copy()
                                        verify_data[param] = verify_payload
                                        verify_resp = self.session.post(self.target, data=verify_data, timeout=10)
                                        if self._payload_reflected(verify_resp.text, verify_payload):
                                            evidence_list.append(f"XSS ({context_name}) in POST param '{param}'")
                                            confirmations += 1
                                            break
                                if confirmations > 0:
                                    break
                            except requests.RequestException:
                                continue
                        if confirmations > 0:
                            break
                    if confirmations > 0:
                        break

            finding.tests_performed = total_payloads
            finding.tests_run = total_payloads

            if confirmations > 0:
                for ev in evidence_list:
                    finding.add_evidence(
                        self._evidence_builder.confirmed(ev, payload=None)
                    )
                finding.confirmations = confirmations
                finding.status = Status.FAIL
                finding.tests_passed = confirmations
                finding.severity = Severity.HIGH
            else:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"No XSS detected. Tested {total_payloads} payloads.",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                finding.tests_passed = total_payloads

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error during XSS scan: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
