"""
Base Scanner - v3.3 (يدعم POST data)
"""

import time
from typing import Optional
from core.finding import Finding, Status, Severity
from core.evidence import EvidenceBuilder
from core.decision_engine import DecisionEngine

class BaseScanner:
    def __init__(self, target: str, session=None, post_data: dict = None):
        self.target = target
        self.session = session
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