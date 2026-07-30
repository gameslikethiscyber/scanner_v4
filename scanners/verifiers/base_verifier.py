import time
import logging
from typing import Optional, Tuple, Any
from core.finding import Finding

logger = logging.getLogger('SeaScanner.Verifier')


class Verifier:
    def __init__(self, session=None):
        self.session = session
        self.name = "BaseVerifier"

    def verify(self, finding: Finding) -> Tuple[bool, str]:
        raise NotImplementedError

    def verify_all(self, findings: list, target_url: str) -> list:
        verified = []
        for finding in findings:
            if not finding.is_vulnerable():
                continue
            try:
                is_verified, message = self.verify(finding)
                if is_verified:
                    finding.verification_status = "verified"
                    finding.confidence = min(100, finding.confidence + 10)
                else:
                    if message == "false_positive":
                        finding.verification_status = "false_positive"
                        finding.status = finding.status.__class__("pass")
                        finding.severity = finding.severity.__class__("none")
                        finding.confidence = 0
                    else:
                        finding.verification_status = "unverified"
                verified.append({"finding": finding, "verified": is_verified, "message": message})
            except Exception as e:
                logger.error("Verifier %s failed: %s", self.name, e)
                verified.append({"finding": finding, "verified": False, "message": str(e)})
        return verified


class SQLiVerifier(Verifier):
    def __init__(self, session=None):
        super().__init__(session)
        self.name = "SQLiVerifier"

    def verify(self, finding: Finding) -> Tuple[bool, str]:
        if "SQL Injection" not in finding.module:
            return False, "not_applicable"

        if not finding.target:
            return False, "no_target"

        import requests
        from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

        sess = self.session or requests.Session()

        payloads_to_try = [
            ("' AND SLEEP(5)-- -", 4),
            ("' OR SLEEP(5)-- -", 4),
            ("' WAITFOR DELAY '00:00:05'-- -", 4),
            ("' AND pg_sleep(5)-- -", 4),
            ("' OR pg_sleep(5)-- -", 4),
        ]

        parsed = urlparse(finding.target)
        params = parse_qs(parsed.query)

        for param_name in params:
            for payload, min_delay in payloads_to_try:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

                try:
                    start = time.time()
                    resp = sess.get(test_url, timeout=15)
                    elapsed = time.time() - start

                    if elapsed >= min_delay:
                        finding.add_evidence(
                            finding._evidence_builder.verified(
                                f"SQLi verified via time delay ({elapsed:.1f}s) using {payload}",
                                payload=payload, parameter=param_name,
                            )
                        )
                        return True, f"time_delay_{elapsed:.1f}s"
                except Exception:
                    continue

        return False, "no_time_delay"


class XSSVerifier(Verifier):
    def __init__(self, session=None):
        super().__init__(session)
        self.name = "XSSVerifier"

    def verify(self, finding: Finding) -> Tuple[bool, str]:
        if "XSS" not in finding.module:
            return False, "not_applicable"
        if not finding.target:
            return False, "no_target"

        import requests
        from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

        sess = self.session or requests.Session()
        parsed = urlparse(finding.target)
        params = parse_qs(parsed.query)

        test_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "{{constructor.constructor('alert(1)')()}}",
        ]

        for param_name in params:
            for payload in test_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

                try:
                    resp = sess.get(test_url, timeout=10)
                    if payload in resp.text:
                        finding.add_evidence(
                            finding._evidence_builder.verified(
                                f"XSS verified - payload reflected in response",
                                payload=payload, parameter=param_name,
                            )
                        )
                        return True, "reflected"
                except Exception:
                    continue

        return False, "no_reflection"
