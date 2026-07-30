import time
import requests
import logging
from enum import Enum
from typing import Optional, Dict, Any, List, Tuple, Callable
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.finding import Finding, Status, Severity
from core.evidence import EvidenceBuilder, EvidenceLevel
from core.decision_engine import DecisionEngine
from core.verification_engine import VerificationEngine, VerificationResult
from core.response_analyzer import ResponseAnalyzer, ResponseAnalysis
from core.payload_mutator import PayloadMutator

logger = logging.getLogger('SeaScanner.Base')

class SmartPayloadSystem:
    def __init__(self):
        self._evidence_builder = EvidenceBuilder()

    def select_payloads(self, param_type: str = "string", detected_tech: List[str] = None) -> Dict[str, List[str]]:
        payloads = {
            'primary': [],
            'confirm': [],
            'cross': [],
        }
        detected_tech = detected_tech or []
        tech_lower = [t.lower() for t in detected_tech]

        if 'mysql' in tech_lower:
            payloads['primary'].append("' OR SLEEP(3)-- -")
            payloads['confirm'].append("' AND SLEEP(2)-- -")
            payloads['cross'].append("'/**/OR/**/1=1-- -")
        elif 'postgresql' in tech_lower:
            payloads['primary'].append("' OR pg_sleep(3)-- -")
            payloads['confirm'].append("' AND pg_sleep(2)-- -")
        elif 'mssql' in tech_lower:
            payloads['primary'].append("' WAITFOR DELAY '00:00:03'-- -")
            payloads['confirm'].append("' WAITFOR DELAY '00:00:02'-- -")
        else:
            payloads['primary'] = ["'", "' OR '1'='1", "' AND '1'='1", "<script>alert(1)</script>"]
            payloads['confirm'] = ['"', "' OR 1=1-- -", "<script>alert(2)</script>"]
            payloads['cross'] = ["'/**/OR/**/1=1-- -", "<img src=x onerror=alert(1)>"]

        if param_type in ('int', 'number'):
            payloads['primary'] = ['1', '0', '-1', '1 OR 1=1']
            payloads['confirm'] = ['2', '0 OR 1=2']

        return payloads

    def encode_payload(self, payload: str, encoding: str = "none") -> str:
        import urllib.parse
        if encoding == "url":
            return urllib.parse.quote(payload, safe='')
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        elif encoding == "unicode":
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == "hex":
            return '0x' + payload.encode('utf-8').hex()
        elif encoding == "base64":
            import base64
            return base64.b64encode(payload.encode()).decode()
        return payload


class BaseScanner:
    def __init__(self, target: str, session=None, post_data: dict = None):
        self.target = target
        self.session = session or requests.Session()
        self.post_data = post_data or {}
        self.name = "BaseScanner"
        self._evidence_builder = EvidenceBuilder()
        self._decision_engine = DecisionEngine()
        self._verification_engine = VerificationEngine(session=self.session)
        self._response_analyzer = ResponseAnalyzer()
        self._smart_payloads = SmartPayloadSystem()
        self._baseline_response = None
        self._baseline_analysis = None

    def scan(self) -> Finding:
        raise NotImplementedError("Subclasses must implement scan() returning Finding")

    def run(self) -> Finding:
        start = time.time()
        finding = self.scan()
        finding.duration = time.time() - start
        finding = self._decision_engine.decide(finding)
        return finding

    def get_params(self) -> list:
        try:
            parsed = urlparse(self.target)
            return list(parse_qs(parsed.query).keys())
        except Exception:
            return []

    def inject_payload(self, param: str, payload: str) -> str:
        try:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            params[param] = [payload]
            return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        except Exception:
            return self.target

    def post_data_with_payload(self, param: str, payload: str) -> Dict[str, Any]:
        data = self.post_data.copy()
        data[param] = payload
        return data

    def inject_payload_with_mutation(self, param: str, payload: str, method: str = 'GET') -> Tuple[Any, str, str]:
        try:
            if method == 'GET':
                test_url = self.inject_payload(param, payload)
                resp = self.session.get(test_url, timeout=10)
            else:
                data = self.post_data_with_payload(param, payload)
                resp = self.session.post(self.target, data=data, timeout=10)

            if resp.status_code == 403:
                mutations = PayloadMutator.generate_mutations(payload)
                for mutated in mutations:
                    try:
                        if method == 'GET':
                            mutated_url = self.inject_payload(param, mutated)
                            mutated_resp = self.session.get(mutated_url, timeout=10)
                        else:
                            mutated_data = self.post_data_with_payload(param, mutated)
                            mutated_resp = self.session.post(self.target, data=mutated_data, timeout=10)
                        if mutated_resp.status_code != 403:
                            return mutated_resp, mutated, "waf_bypass"
                    except Exception:
                        continue
            return resp, payload, "standard"
        except Exception:
            return None, payload, "error"

    def create_finding(self) -> Finding:
        return Finding()

    def create_safe_finding(self, reason: str = "No vulnerabilities detected", evidence: str = "") -> Finding:
        finding = self.create_finding()
        finding.status = Status.PASS
        finding.severity = Severity.NONE
        finding.confidence = 93
        finding.reason = reason
        finding.evidence_text = evidence
        finding.recommendation = "Continue monitoring"
        finding.target = self.target
        return finding

    def create_vulnerable_finding(self, severity: Severity, reason: str, evidence: str,
                                  recommendation: str, confidence: int = 85) -> Finding:
        finding = self.create_finding()
        finding.status = Status.FAIL
        finding.severity = severity
        finding.confidence = confidence
        finding.reason = reason
        finding.evidence_text = evidence
        finding.recommendation = recommendation
        finding.target = self.target
        return finding

    def get_baseline(self) -> Tuple[Optional[Any], Optional[ResponseAnalysis]]:
        if self._baseline_response is not None:
            return self._baseline_response, self._baseline_analysis
        try:
            resp = self.session.get(self.target, timeout=10)
            if resp.status_code == 200:
                self._baseline_response = resp
                self._baseline_analysis = ResponseAnalyzer.analyze_response(resp)
                return resp, self._baseline_analysis
        except Exception:
            pass
        return None, None

    def get_baseline_time(self, method: str = 'GET', samples: int = 3) -> Optional[float]:
        times = []
        for _ in range(samples):
            try:
                start = time.time()
                if method == 'GET':
                    self.session.get(self.target, timeout=10)
                else:
                    self.session.post(self.target, data=self.post_data or {}, timeout=10)
                times.append(time.time() - start)
            except requests.RequestException:
                pass
        if not times:
            return None
        times.sort()
        return times[len(times) // 2]

    def add_evidence_with_snippet(self, finding, level, description, payload=None, parameter=None, response=None, method='GET'):
        snippet = ''
        headers = {}
        timing = None
        if response is not None:
            snippet = response.text[:200]
            headers = dict(response.headers)
            timing = getattr(response, 'elapsed', None)
            if timing is not None:
                timing = timing.total_seconds()

        kwargs = {
            'payload': payload,
            'parameter': parameter,
            'method': method,
        }
        ev_raw_data = {}
        if snippet:
            ev_raw_data['snippet'] = snippet
        if headers:
            ev_raw_data['headers'] = dict(list(headers.items())[:10])
        if timing is not None:
            ev_raw_data['timing'] = timing

        if level == 'confirmed':
            ev = self._evidence_builder.confirmed(description, **kwargs)
        elif level == 'likely':
            ev = self._evidence_builder.likely(description, **kwargs)
        elif level == 'possible':
            ev = self._evidence_builder.possible(description, **kwargs)
        elif level == 'verified':
            ev = self._evidence_builder.verified(description, **kwargs)
        elif level == 'error':
            ev = self._evidence_builder.error(description, **kwargs)
        else:
            ev = self._evidence_builder.possible(description, **kwargs)

        ev.raw_data = ev_raw_data
        finding.add_evidence(ev)

    def capture_http_evidence(
        self,
        finding,
        description: str,
        response,
        payload: Optional[str] = None,
        parameter: Optional[str] = None,
        method: str = 'GET',
    ):
        request_info = {
            'method': method,
            'url': self.target,
            'headers': dict(self.session.headers),
            'payload': payload,
        }
        response_info = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'body_snippet': response.text[:500],
            'body_length': len(response.text),
            'elapsed': response.elapsed.total_seconds() if response.elapsed else None,
            'analysis': ResponseAnalyzer.analyze_response(response).__dict__ if response else {},
        }
        ev = self._evidence_builder.request_response(
            description,
            request=request_info,
            response=response_info,
            payload=payload,
            endpoint=self.target,
            parameter=parameter,
            method=method,
        )
        finding.add_evidence(ev)

    def verify_multi_pass(
        self,
        param: str,
        primary_payload: str,
        confirm_payload: str,
        cross_payload: Optional[str] = None,
        method: str = 'GET',
        primary_check: Optional[Callable] = None,
    ) -> Tuple[bool, int, List[VerificationResult]]:
        def make_request(payload):
            if method == 'GET':
                test_url = self.inject_payload(param, payload)
                return self.session.get(test_url, timeout=10)
            else:
                data = self.post_data_with_payload(param, payload)
                return self.session.post(self.target, data=data, timeout=10)

        def check_response(response):
            if response is None:
                return False, "", {}
            return True, f"HTTP {response.status_code}", {'response': response}

        def wrapped_primary():
            return make_request(primary_payload)

        def wrapped_confirm():
            return make_request(confirm_payload)

        def wrapped_cross():
            if cross_payload:
                return make_request(cross_payload)
            return None

        passes, confidence, details = self._verification_engine.run_multi_pass(
            primary_test=wrapped_primary,
            confirm_test=wrapped_confirm,
            cross_test=wrapped_cross if cross_payload else None,
            param=param,
            payload=primary_payload,
            method=method,
        )

        return len([p for p in passes if p.passed]) >= 2, confidence, passes

    def add_verification_evidence(self, finding, passes: List[VerificationResult], param: str, payload: str, method: str = 'GET'):
        passed_count = sum(1 for p in passes if p.passed)
        total_count = len(passes)

        ev = self._verification_engine.build_evidence_from_verification(
            passes, param=param, payload=payload, method=method, endpoint=self.target
        )
        if ev:
            ev.verification_pass = passed_count
            ev.verification_method = f"{passed_count}/{total_count} passes"
            finding.add_evidence(ev)

        if passed_count >= 2:
            finding.cross_validated = True
            finding.cvss_explanation = (
                f"Vulnerability confirmed via {passed_count}/{total_count} "
                f"verification passes with evidence from multiple payloads"
            )

    def add_payload_evidence(self, finding, payload: str, param: str = ""):
        if payload and payload not in finding.payload_evidence:
            finding.payload_evidence.append(payload)

    def capture_response_analysis(self, finding, response, label: str = "response"):
        analysis = ResponseAnalyzer.analyze_response(response)
        if analysis.has_errors:
            for err in analysis.error_messages[:3]:
                finding.add_evidence(
                    self._evidence_builder.possible(
                        f"Error in {label}: {err}",
                        endpoint=self.target,
                    )
                )
        for tech in analysis.technologies:
            if tech not in finding.fingerprint.get('technologies', []):
                if 'technologies' not in finding.fingerprint:
                    finding.fingerprint['technologies'] = []
                finding.fingerprint['technologies'].append(tech)
