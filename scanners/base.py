"""
Base Scanner - v3.5 (Shared methods for params/payload injection)
"""

import time
import requests
from typing import Optional, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.finding import Finding, Status, Severity
from core.evidence import EvidenceBuilder
from core.decision_engine import DecisionEngine

class BaseScanner:
    def __init__(self, target: str, session=None, post_data: dict = None):
        self.target = target
        self.session = session or requests.Session()
        self.post_data = post_data or {}
        self.name = "BaseScanner"
        self._evidence_builder = EvidenceBuilder()
        self._decision_engine = DecisionEngine()

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
        return finding

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