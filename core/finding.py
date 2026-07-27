"""
Unified Finding Structure - v3.1 (Full)
"""

from enum import Enum
from datetime import datetime
from typing import Optional, List, Dict, Any

class Severity(Enum):
    NONE = "none"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Status(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"
    SAFE = "safe"
    VULNERABLE = "vulnerable"
    ERROR = "error"
    INFO = "info"

class Exploitability(Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    THEORETICAL = "theoretical"
    UNKNOWN = "unknown"

class Finding:
    def __init__(self):
        self.id: str = ""
        self.module: str = ""
        self.title: str = ""
        self.description: str = ""

        self.status: Status = Status.UNKNOWN
        self.evidence_level: str = "unknown"
        self.confidence: int = 0
        self.confidence_factors: Dict[str, int] = {}

        self.severity: Severity = Severity.NONE
        self.exploitability: Exploitability = Exploitability.UNKNOWN
        self.impact: Dict[str, int] = {
            'confidentiality': 0,
            'integrity': 0,
            'availability': 0
        }

        self.cvss_score: float = 0.0
        self.cwe_id: str = ""
        self.owasp_category: str = ""
        self.capec_id: str = ""

        self.evidence: List[Any] = []
        self.requests_made: List[Dict[str, Any]] = []
        self.responses_received: List[Dict[str, Any]] = []

        self.recommendations: List[Dict[str, Any]] = []
        self.references: List[str] = []

        self.fingerprint: Dict[str, Any] = {}
        self.conditions: List[Dict[str, Any]] = []
        self.raw_data: Dict[str, Any] = {}
        self.duration: float = 0.0
        self.tests_performed: int = 0

        # Backward compatibility
        self.module_name: str = ""
        self.findings: List[Dict[str, Any]] = []
        self.tests_run: int = 0
        self.tests_passed: int = 0
        self.confirmations: int = 0
        self.heuristics: int = 0
        self.false_positive_risk: float = 0.0
        self.scan_errors: int = 0
        self.timeout: bool = False
        self.duration_ms: int = 0
        self.meta: Dict[str, Any] = {}

        self.reason: str = ""
        self.evidence_text: str = ""
        self.recommendation: str = ""
        self.skipped: bool = False
        self.skip_reason: str = ""
        self.details: Dict[str, Any] = {}
        self.detection_methods: List[str] = []
        self.evidence_quality: int = 0
        self.timestamp: str = datetime.now().isoformat()

    def is_skipped(self) -> bool:
        return self.skipped or self.status == Status.SKIPPED

    def is_safe(self) -> bool:
        return self.status == Status.SAFE or self.status == Status.PASS

    def is_vulnerable(self) -> bool:
        return self.status == Status.VULNERABLE or self.status == Status.FAIL

    def add_evidence(self, evidence: Any) -> None:
        self.evidence.append(evidence)
        self._update_confidence_from_evidence()

    def _update_confidence_from_evidence(self) -> None:
        if not self.evidence:
            self.confidence = 0
            return

        base = 0
        factors: Dict[str, int] = {}
        has_error = False

        for ev in self.evidence:
            bonus = getattr(ev, 'confidence_bonus', 0)
            desc = getattr(ev, 'description', '')[:30]

            if 'error' in getattr(ev, 'description', '').lower():
                has_error = True
                bonus = min(bonus, -20)

            base += bonus
            if bonus != 0:
                factors[f"Evidence: {desc}"] = bonus

        if len(self.evidence) >= 2 and not has_error:
            base += 5
            factors["Multiple Evidences"] = 5

        max_confidence = 95
        if any(getattr(ev, 'level', None) == 'exploited' for ev in self.evidence):
            max_confidence = 100
        elif any(getattr(ev, 'level', None) == 'verified' for ev in self.evidence):
            max_confidence = 90
        elif any(getattr(ev, 'level', None) == 'confirmed' for ev in self.evidence):
            max_confidence = 85
        elif any(getattr(ev, 'level', None) == 'likely' for ev in self.evidence):
            max_confidence = 75
        elif any(getattr(ev, 'level', None) == 'possible' for ev in self.evidence):
            max_confidence = 60

        if has_error:
            max_confidence = min(max_confidence, 40)
            factors["⚠️ Error detected"] = -10

        self.confidence = max(0, min(max_confidence, base))
        self.confidence_factors = factors

    def add_recommendation(self, priority: int, action: str, why: str, how: str, references: Optional[List[str]] = None) -> None:
        self.recommendations.append({
            'priority': priority,
            'action': action,
            'why': why,
            'how': how,
            'references': references or []
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "module": self.module,
            "module_name": self.module_name,
            "title": self.title,
            "description": self.description,
            "status": self.status.value if hasattr(self.status, 'value') else str(self.status),
            "evidence_level": self.evidence_level,
            "confidence": self.confidence,
            "confidence_factors": self.confidence_factors,
            "severity": self.severity.value if hasattr(self.severity, 'value') else str(self.severity),
            "exploitability": self.exploitability.value if hasattr(self.exploitability, 'value') else str(self.exploitability),
            "impact": self.impact,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "capec_id": self.capec_id,
            "evidence": [e.to_dict() if hasattr(e, 'to_dict') else e for e in self.evidence],
            "recommendations": self.recommendations,
            "references": self.references,
            "fingerprint": self.fingerprint,
            "conditions": self.conditions,
            "duration": self.duration,
            "tests_performed": self.tests_performed,
            "tests_run": self.tests_run,
            "tests_passed": self.tests_passed,
            "confirmations": self.confirmations,
            "heuristics": self.heuristics,
            "false_positive_risk": self.false_positive_risk,
            "scan_errors": self.scan_errors,
            "timeout": self.timeout,
            "duration_ms": self.duration_ms,
            "meta": self.meta,
            "reason": self.reason,
            "evidence_text": self.evidence_text,
            "recommendation": self.recommendation,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "details": self.details,
            "detection_methods": self.detection_methods,
            "evidence_quality": self.evidence_quality,
            "timestamp": self.timestamp
        }


# ===== ScanResult =====
class ScanResult:
    def __init__(self, findings: Optional[List[Finding]] = None):
        self.findings: List[Finding] = findings or []
        self.start_time: datetime = datetime.now()
        self.end_time: Optional[datetime] = None
        self.requests_sent: int = 0
        self.injection_payloads: int = 0
        self.headers_tests: int = 0
        self.port_tests: int = 0
        self.pages_crawled: int = 0
        self.total_modules: int = 0

    def add_finding(self, finding: Finding) -> None:
        if finding.tests_run == 0 and finding.tests_performed > 0:
            finding.tests_run = finding.tests_performed
        if finding.tests_passed == 0 and finding.tests_performed > 0:
            finding.tests_passed = finding.tests_performed
        if finding.tests_performed == 0 and finding.tests_run > 0:
            finding.tests_performed = finding.tests_run
        if not finding.module_name and finding.module:
            finding.module_name = finding.module
        elif not finding.module and finding.module_name:
            finding.module = finding.module_name
        self.findings.append(finding)

    def get_vulnerabilities(self) -> List[Finding]:
        return [f for f in self.findings if f.is_vulnerable()]

    def get_safe_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.is_safe()]

    def get_info_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.status == Status.INFO]

    def get_warning_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.status == Status.WARNING]

    def get_skipped_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.is_skipped()]

    def get_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def get_critical(self) -> List[Finding]:
        return self.get_by_severity(Severity.CRITICAL)

    def get_high(self) -> List[Finding]:
        return self.get_by_severity(Severity.HIGH)

    def get_medium(self) -> List[Finding]:
        return self.get_by_severity(Severity.MEDIUM)

    def get_low(self) -> List[Finding]:
        return self.get_by_severity(Severity.LOW)

    def get_highest_severity(self) -> Severity:
        vulnerabilities = self.get_vulnerabilities()
        if not vulnerabilities:
            return Severity.NONE
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for sev in severity_order:
            if any(f.severity == sev for f in vulnerabilities):
                return sev
        return Severity.NONE

    def get_coverage(self) -> Dict[str, Any]:
        total = self.total_modules
        executed = len([f for f in self.findings if not f.is_skipped()])
        skipped = len(self.get_skipped_findings())
        failed = len([f for f in self.findings if f.status == Status.ERROR])
        not_applicable = len(self.get_info_findings())
        if total <= 0:
            total = len(self.findings)
            executed = len(self.findings) - skipped - failed
        coverage = int((executed / total) * 100) if total > 0 else 0
        return {
            'total': total,
            'executed': executed,
            'skipped': skipped,
            'failed': failed,
            'not_applicable': not_applicable,
            'coverage': coverage
        }

    def calculate_dynamic_risk_score(self) -> int:
        vulnerabilities = self.get_vulnerabilities()
        if not vulnerabilities:
            return 0
        severity_weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 2
        }
        total_weighted_risk = 0
        max_possible_risk = 0
        for finding in vulnerabilities:
            weight = severity_weights.get(finding.severity, 0)
            confidence = finding.confidence / 100
            weighted_risk = weight * confidence
            total_weighted_risk += weighted_risk
            max_possible_risk += weight
        if max_possible_risk > 0:
            return int((total_weighted_risk / max_possible_risk) * 100)
        return 0

    def get_overall_severity(self) -> Dict[str, str]:
        highest = self.get_highest_severity()
        severity_map = {
            Severity.CRITICAL: {
                'label': '🔥 Critical Risk',
                'description': 'Immediate action required. Critical vulnerabilities found.',
                'color': '#f44336'
            },
            Severity.HIGH: {
                'label': '🚨 High Risk',
                'description': 'Urgent action required. High-risk vulnerabilities found.',
                'color': '#FF9800'
            },
            Severity.MEDIUM: {
                'label': '⚠️ Medium Risk',
                'description': 'Action recommended. Medium-risk issues found.',
                'color': '#FFC107'
            },
            Severity.LOW: {
                'label': '🟡 Low Risk',
                'description': 'Informational. Low-risk findings for best practice improvements.',
                'color': '#4CAF50'
            },
            Severity.NONE: {
                'label': '✅ No Risk',
                'description': 'System appears secure. No vulnerabilities detected.',
                'color': '#2196F3'
            }
        }
        return severity_map.get(highest, severity_map[Severity.NONE])

    def validate(self) -> List[str]:
        errors = []
        critical_count = len(self.get_critical())
        if critical_count != len([f for f in self.findings if f.severity == Severity.CRITICAL]):
            errors.append("Critical count mismatch")
        for finding in self.findings:
            if finding.is_safe() and finding.severity != Severity.NONE:
                errors.append(f"Finding '{finding.module}' has severity but status SAFE")
            if finding.is_vulnerable() and finding.severity == Severity.NONE:
                errors.append(f"Finding '{finding.module}' is vulnerable but severity NONE")
            if finding.is_vulnerable() and finding.confidence < 30:
                errors.append(f"Finding '{finding.module}' has low confidence ({finding.confidence}%)")
        return errors

    def get_statistics(self) -> Dict[str, Any]:
        vulnerabilities = self.get_vulnerabilities()
        coverage = self.get_coverage()
        overall = self.get_overall_severity()
        highest = self.get_highest_severity()
        risk_score = self.calculate_dynamic_risk_score()
        return {
            "total": len(self.findings),
            "vulnerabilities": len(vulnerabilities),
            "safe": len(self.get_safe_findings()),
            "info": len(self.get_info_findings()),
            "warning": len(self.get_warning_findings()),
            "critical": len(self.get_critical()),
            "high": len(self.get_high()),
            "medium": len(self.get_medium()),
            "low": len(self.get_low()),
            "duration": (self.end_time - self.start_time).total_seconds() if self.end_time else 0,
            "requests_sent": self.requests_sent,
            "injection_payloads": self.injection_payloads,
            "headers_tests": self.headers_tests,
            "port_tests": self.port_tests,
            "pages_crawled": self.pages_crawled,
            "risk_score": risk_score,
            "overall_severity": overall['label'],
            "overall_description": overall['description'],
            "overall_color": overall['color'],
            "highest_severity": highest.value if highest else 'none',
            "scanner_version": "1.0.0",
            "report_version": "2.0",
            "coverage_total": coverage['total'],
            "coverage_executed": coverage['executed'],
            "coverage_skipped": coverage['skipped'],
            "coverage_failed": coverage['failed'],
            "coverage_not_applicable": coverage['not_applicable'],
            "coverage_percentage": coverage['coverage']
        }