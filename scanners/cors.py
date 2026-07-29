import requests
import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.CORS')

_SEV_W = {Severity.NONE: 0, Severity.INFO: 1, Severity.LOW: 2,
          Severity.MEDIUM: 3, Severity.HIGH: 4, Severity.CRITICAL: 5}

class CORSScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "CORS Configuration"
        self.test_origins = ['https://evil.com', 'https://attacker.com', 'null', '*']
        self.trusted_origins = []

    def set_trusted_origins(self, origins):
        self.trusted_origins = list(origins)

    def _is_trusted(self, origin):
        return any(trusted in origin for trusted in self.trusted_origins)

    def _escalate_to(self, current, target):
        return target if _SEV_W[target] > _SEV_W[current] else current

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            severity = Severity.NONE
            has_issues = False
            detection_methods = []

            for origin in self.test_origins:
                try:
                    resp = self.session.get(self.target, headers={'Origin': origin}, timeout=10)
                    acao = resp.headers.get('Access-Control-Allow-Origin')
                    acac = resp.headers.get('Access-Control-Allow-Credentials')
                    vary = resp.headers.get('Vary', '')

                    if not acao:
                        continue

                    if self._is_trusted(origin):
                        continue

                    has_issues = True

                    if acao == origin:
                        if origin == 'null':
                            finding.add_evidence(
                                self._evidence_builder.likely(
                                    "'null' origin is allowed (risky for sandboxed iframes)",
                                    payload=origin
                                )
                            )
                            severity = self._escalate_to(severity, Severity.MEDIUM)
                            detection_methods.append('null_origin')
                        else:
                            self.capture_http_evidence(
                                finding,
                                f"Origin '{origin}' reflected in ACAO (arbitrary origin reflection)",
                                resp, payload=origin
                            )
                            severity = self._escalate_to(severity, Severity.HIGH)
                            detection_methods.append('origin_reflection')

                    if acao == '*':
                        self.capture_http_evidence(
                            finding,
                            "Wildcard origin allowed (*)",
                            resp, payload=origin
                        )
                        severity = self._escalate_to(severity, Severity.HIGH)
                        detection_methods.append('wildcard_origin')

                    if acac and acac.lower() == 'true':
                        if acao == '*':
                            self.capture_http_evidence(
                                finding,
                                "Credentials allowed with wildcard origin (critical misconfiguration)",
                                resp, payload=origin
                            )
                            severity = Severity.CRITICAL
                            detection_methods.append('wildcard_credentials')
                        else:
                            finding.add_evidence(
                                self._evidence_builder.likely(
                                    f"Credentials allowed with ACAO: {acao}",
                                    payload=origin
                                )
                            )
                            detection_methods.append('credentials_with_acao')
                            severity = self._escalate_to(severity, Severity.MEDIUM)

                    if vary and 'Origin' not in vary:
                        finding.add_evidence(
                            self._evidence_builder.possible(
                                "Vary: Origin header is missing (may cause caching issues)",
                                payload=origin
                            )
                        )

                except requests.RequestException:
                    continue

            try:
                opt_resp = self.session.options(
                    self.target,
                    headers={'Origin': 'https://evil.com', 'Access-Control-Request-Method': 'GET'},
                    timeout=10,
                )
                opt_acao = opt_resp.headers.get('Access-Control-Allow-Origin')
                if opt_acao and not self._is_trusted(opt_acao):
                    if opt_acao == '*' or opt_acao == 'https://evil.com':
                        self.capture_http_evidence(
                            finding,
                            "Preflight (OPTIONS) confirms CORS misconfiguration",
                            opt_resp, payload=opt_acao
                        )
                        has_issues = True
                        detection_methods.append('preflight_confirmed')
                        if Severity.HIGH.value > severity.value:
                            severity = Severity.HIGH
            except requests.RequestException:
                pass

            finding.tests_performed = len(self.test_origins) + 1
            finding.tests_run = finding.tests_performed
            finding.detection_methods = detection_methods

            if has_issues:
                finding.status = Status.FAIL
                finding.tests_passed = 0
                finding.severity = severity if severity != Severity.NONE else Severity.LOW
                finding.add_recommendation(
                    1, "Restrict CORS to specific trusted origins",
                    "Allowing '*' or reflecting any origin can lead to data theft via cross-origin attacks.",
                    "Set Access-Control-Allow-Origin to a specific trusted domain.",
                    ["OWASP: CORS Security", "Mozilla: CORS"]
                )
            else:
                finding.add_evidence(
                    self._evidence_builder.verified("No CORS misconfigurations detected", payload=None)
                )
                finding.status = Status.PASS
                finding.tests_passed = finding.tests_performed

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error scanning CORS: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding
