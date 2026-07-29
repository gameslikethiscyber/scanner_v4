import re
import requests
import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner
from core.response_analyzer import ResponseAnalyzer

logger = logging.getLogger('SeaScanner.XSS')

class XSSScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "XSS Detection"

        self.contexts = {
            'html': {
                'payloads': [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "<body onload=alert(1)>",
                ],
                'verify_payloads': [
                    "<script>alert(2)</script>",
                    "<img src=x onerror=alert(2)>",
                    "<svg onload=alert(2)>",
                ],
                'cross_payloads': [
                    "<script>prompt(1)</script>",
                    "<img src=x onerror=prompt(1)>",
                ],
            },
            'attribute': {
                'payloads': [
                    '" onfocus=alert(1) autofocus ',
                    "' onfocus=alert(1) autofocus ",
                    '" onclick=alert(1) ',
                    "' onclick=alert(1) ",
                ],
                'verify_payloads': [
                    '" onfocus=alert(2) autofocus ',
                    "' onfocus=alert(2) autofocus ",
                ],
                'cross_payloads': [
                    '" onfocus=prompt(1) autofocus ',
                    "' onfocus=prompt(1) autofocus ",
                ],
            },
            'javascript': {
                'payloads': [
                    "';alert(1);//",
                    '";alert(1);//',
                    "';confirm(1);//",
                ],
                'verify_payloads': [
                    "';alert(2);//",
                    '";alert(2);//',
                ],
                'cross_payloads': [
                    "';prompt(1);//",
                    '";prompt(1);//',
                ],
            },
        }

        self.reflection_patterns = [
            r'<script>.*?alert',
            r'onerror=.*?alert',
            r'onfocus=.*?alert',
            r'onload=.*?alert',
            r';alert',
            r'onclick=.*?alert',
            r'<script>.*?prompt',
            r'onerror=.*?prompt',
        ]

    def _payload_reflected(self, resp_text, payload):
        escaped_payload = re.escape(payload[:20])
        return bool(re.search(escaped_payload, resp_text, re.IGNORECASE))

    def _check_context_reflection(self, resp_text, pattern):
        return bool(re.search(pattern, resp_text, re.IGNORECASE))

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
            detected_contexts = set()

            if params:
                result = self._test_params(params, method='GET')
                total_payloads += result['payloads_tested']
                confirmations += result['confirmations']
                evidence_list.extend(result['evidence'])
                detected_contexts.update(result['contexts'])

            if post_params and confirmations == 0:
                post_keys = list(post_params.keys())
                result = self._test_params(post_keys, method='POST')
                total_payloads += result['payloads_tested']
                confirmations += result['confirmations']
                evidence_list.extend(result['evidence'])
                detected_contexts.update(result['contexts'])

            finding.tests_performed = total_payloads
            finding.tests_run = total_payloads

            if confirmations > 0:
                for ev in evidence_list:
                    finding.add_evidence(self._evidence_builder.confirmed(ev, payload=None))
                finding.confirmations = confirmations
                finding.status = Status.FAIL
                finding.tests_passed = confirmations
                finding.severity = Severity.HIGH
                finding.detection_methods = [f"{ctx} context" for ctx in detected_contexts]

                if len(detected_contexts) >= 2:
                    finding.cross_validated = True
                    finding.verification_passes = len(detected_contexts)
                    finding.confidence = min(100, finding.confidence + 10)
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

    def _test_params(self, params, method='GET'):
        confirmations = 0
        evidence_list = []
        total_payloads = 0
        detected_contexts = set()

        for context_name in self.contexts:
            ctx = self.contexts[context_name]
            for param in params:
                for payload in ctx['payloads']:
                    total_payloads += 1
                    try:
                        if method == 'GET':
                            test_url = self.inject_payload(param, payload)
                            resp = self.session.get(test_url, timeout=10)
                        else:
                            data = self.post_data.copy()
                            data[param] = payload
                            resp = self.session.post(self.target, data=data, timeout=10)

                        if not self._payload_reflected(resp.text, payload):
                            continue

                        for pattern in self.reflection_patterns:
                            if self._check_context_reflection(resp.text, pattern):
                                verify_payload = ctx['verify_payloads'][0]
                                if method == 'GET':
                                    verify_url = self.inject_payload(param, verify_payload)
                                    verify_resp = self.session.get(verify_url, timeout=10)
                                else:
                                    verify_data = self.post_data.copy()
                                    verify_data[param] = verify_payload
                                    verify_resp = self.session.post(self.target, data=verify_data, timeout=10)

                                if self._payload_reflected(verify_resp.text, verify_payload):
                                    cross_payload = ctx.get('cross_payloads', [None])[0]
                                    if cross_payload:
                                        cross_reflected = False
                                        try:
                                            if method == 'GET':
                                                cross_url = self.inject_payload(param, cross_payload)
                                                cross_resp = self.session.get(cross_url, timeout=10)
                                            else:
                                                cross_data = self.post_data.copy()
                                                cross_data[param] = cross_payload
                                                cross_resp = self.session.post(self.target, data=cross_data, timeout=10)
                                            cross_reflected = self._payload_reflected(cross_resp.text, cross_payload)
                                        except Exception:
                                            pass
                                        if cross_reflected:
                                            evidence_list.append(f"XSS ({context_name}) in {method} param '{param}' (multi-verified)")
                                            confirmations += 1
                                            detected_contexts.add(context_name)
                                            break
                                    else:
                                        evidence_list.append(f"XSS ({context_name}) in {method} param '{param}' (verified)")
                                        confirmations += 1
                                        detected_contexts.add(context_name)
                                        break
                                if confirmations > 0:
                                    break
                        if confirmations > 0:
                            break
                    except requests.RequestException:
                        continue
                if confirmations > 0:
                    break
            if confirmations > 0:
                break

        return {
            'confirmations': confirmations,
            'evidence': evidence_list,
            'payloads_tested': total_payloads,
            'contexts': detected_contexts,
        }
