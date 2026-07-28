"""
Unified Finding Structure - v3.1 (Full)
"""

from enum import Enum
from datetime import datetime
from typing import Optional, List, Dict, Any
from threading import Lock
from core.evidence import EvidenceLevel

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
        self.cvss_vector: str = ""
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

        # Production-quality fields
        self.occurrences: int = 1
        self.affected_urls: List[str] = []
        self.verification_status: str = "unverified"
        self.target: str = ""

        # Commercial-grade fields
        self.verify_commands: List[str] = []
        self.replay_data: Dict[str, Any] = {}
        self.cvss_explanation: str = ""
        self.mitre_id: str = ""
        self.asvs_reference: str = ""
        self.security_grade: str = ""
        self.risk_level: str = ""

    @property
    def _dedup_key(self) -> str:
        evidence_desc = ''
        if self.evidence:
            ev = self.evidence[0]
            evidence_desc = getattr(ev, 'description', '') or ''
        return f"{self.module}|{evidence_desc[:80]}"

    def merge(self, other: 'Finding') -> None:
        self.occurrences += other.occurrences
        if other.target and other.target not in self.affected_urls:
            self.affected_urls.append(other.target)
        for ev in other.evidence:
            desc = getattr(ev, 'description', '') or ''
            existing = any(
                desc == (getattr(e, 'description', '') or '')
                for e in self.evidence
            )
            if not existing:
                self.evidence.append(ev)
        self.tests_performed += other.tests_performed
        self.tests_run += other.tests_run
        self.tests_passed += other.tests_passed
        self.duration = max(self.duration, other.duration)

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

        factors: Dict[str, int] = {}
        has_error = False

        total_weight = 0
        weighted_bonus = 0

        for ev in self.evidence:
            bonus = getattr(ev, 'confidence_bonus', 0)
            weight = getattr(ev, 'weight', 1)
            desc = getattr(ev, 'description', '')[:30]

            level = getattr(ev, 'level', None)
            if level is EvidenceLevel.UNKNOWN and 'error' in getattr(ev, 'description', '').lower():
                has_error = True
                bonus = min(bonus, -20)

            if bonus > 0:
                weighted_bonus += bonus * weight
                total_weight += weight
                if bonus != 0:
                    factors[f"Evidence: {desc}"] = bonus

        if total_weight > 0:
            base = weighted_bonus // total_weight + 50
        else:
            base = 50

        if len(self.evidence) >= 2 and not has_error:
            base += 5
            factors["Multiple Evidences"] = 5

        max_confidence = 95
        has_exploited = False
        has_verified = False
        for ev in self.evidence:
            level = getattr(ev, 'level', None)
            if level is EvidenceLevel.EXPLOITED:
                max_confidence = 100
                has_exploited = True
            elif level is EvidenceLevel.VERIFIED:
                if not has_exploited:
                    max_confidence = 90
                has_verified = True
            elif level is EvidenceLevel.CONFIRMED:
                if not has_exploited and not has_verified:
                    max_confidence = 85
            elif level is EvidenceLevel.LIKELY:
                if not has_exploited and not has_verified and max_confidence > 85:
                    max_confidence = 75
            elif level is EvidenceLevel.POSSIBLE:
                if max_confidence > 75:
                    max_confidence = 60

        if has_error:
            max_confidence = min(max_confidence, 40)
            factors["Error detected"] = -10

        self.confidence = max(0, min(max_confidence, base))
        self.confidence_factors = factors

        self._update_verification_status()

    def _update_verification_status(self) -> None:
        levels = [getattr(ev, 'level', None) for ev in self.evidence]
        if EvidenceLevel.EXPLOITED in levels:
            self.verification_status = "verified"
        elif EvidenceLevel.VERIFIED in levels:
            self.verification_status = "verified"
        elif EvidenceLevel.CONFIRMED in levels:
            self.verification_status = "likely"
        elif EvidenceLevel.LIKELY in levels:
            self.verification_status = "possible"
        elif EvidenceLevel.POSSIBLE in levels:
            self.verification_status = "manual_review"
        else:
            self.verification_status = "unverified"

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
            "timestamp": self.timestamp,
            "occurrences": self.occurrences,
            "affected_urls": self.affected_urls,
            "verification_status": self.verification_status,
            "target": self.target,
            "verify_commands": self.verify_commands,
            "replay_data": self.replay_data,
            "cvss_explanation": self.cvss_explanation,
            "mitre_id": self.mitre_id,
            "asvs_reference": self.asvs_reference,
            "security_grade": self.security_grade,
            "risk_level": self.risk_level,
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
        self._lock: Lock = Lock()

        # Attack surface inventory
        self.urls_discovered: List[str] = []
        self.urls_crawled: int = 0
        self.urls_skipped: int = 0
        self.useful_pages: int = 0
        self.not_useful_pages: int = 0
        self.js_discovered_urls: int = 0
        self.api_endpoints: List[str] = []
        self.forms_discovered: int = 0
        self.hidden_inputs: int = 0
        self.params_discovered: int = 0
        self.directories_discovered: List[str] = []
        self.interesting_files: List[str] = []
        self.js_files: List[str] = []
        self.technologies: List[str] = []
        self.cookies_found: int = 0
        self.headers_found: Dict[str, str] = {}
        self.authentication_pages: List[str] = []
        self.admin_pages: List[str] = []
        self.skip_reasons: Dict[str, List[str]] = {}
        self.crawler_type: str = "http"

    def add_finding(self, finding: Finding) -> None:
        with self._lock:
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

            # Deduplication: PASS findings merge by module only
            if finding.is_safe():
                for existing in self.findings:
                    if existing.is_safe() and existing.module == finding.module:
                        existing.occurrences += 1
                        if finding.target and finding.target not in existing.affected_urls:
                            existing.affected_urls.append(finding.target)
                        existing.tests_performed += finding.tests_performed
                        existing.tests_run += finding.tests_run
                        existing.tests_passed += finding.tests_passed
                        return
                self.findings.append(finding)
                return

            # Deduplication: FAIL/WARNING findings merge by module + evidence
            dedup_key = finding._dedup_key
            for existing in self.findings:
                if existing._dedup_key == dedup_key:
                    existing.merge(finding)
                    return

            self.findings.append(finding)

    def aggregate_safe_findings(self):
        """Aggregate PASS findings by module, summing page/test counts."""
        safe = [f for f in self.findings if f.is_safe()]
        others = [f for f in self.findings if not f.is_safe()]
        merged = {}
        for f in safe:
            key = f.module
            if key in merged:
                m = merged[key]
                m.occurrences += f.occurrences
                if f.target and f.target not in m.affected_urls:
                    m.affected_urls.append(f.target)
                m.tests_performed += f.tests_performed
                m.tests_run += f.tests_run
                m.tests_passed += f.tests_passed
            else:
                merged[key] = f
        self.findings = others + list(merged.values())

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

        # Build per-module skip reasons
        skip_reasons = {}
        for f in self.findings:
            if f.is_skipped() and f.skip_reason:
                key = f.skip_reason[:60]
                if key not in skip_reasons:
                    skip_reasons[key] = []
                skip_reasons[key].append(f.module)

        return {
            'total': total,
            'executed': executed,
            'skipped': skipped,
            'failed': failed,
            'not_applicable': not_applicable,
            'coverage': coverage,
            'skip_reasons': skip_reasons,
        }

    def calculate_dynamic_risk_score(self) -> int:
        from core.decision_engine import RiskCalculator
        result = RiskCalculator.calculate(self.findings)
        return int(result["risk_score"])

    def calculate_risk_breakdown(self) -> Dict[str, Any]:
        from core.decision_engine import RiskCalculator
        return RiskCalculator.calculate(self.findings)

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

        fail_findings = [f for f in self.findings if f.status in (Status.FAIL, Status.VULNERABLE)]
        critical_count = len([f for f in fail_findings if f.severity == Severity.CRITICAL])
        high_count = len([f for f in fail_findings if f.severity == Severity.HIGH])
        medium_count = len([f for f in fail_findings if f.severity == Severity.MEDIUM])
        low_count = len([f for f in fail_findings if f.severity == Severity.LOW])
        safe_count = len(self.get_safe_findings())
        info_count = len(self.get_info_findings())
        warning_count = len(self.get_warning_findings())

        # Build smart executive summary
        vuln_count = len(vulnerabilities)
        has_critical = critical_count > 0
        has_high = high_count > 0
        has_medium = medium_count > 0
        verified_vulns = sum(1 for f in vulnerabilities if f.verification_status == "verified")
        likely_vulns = sum(1 for f in vulnerabilities if f.verification_status == "likely")

        if has_critical:
            executive = (
                f"Critical vulnerabilities detected ({critical_count} critical, {high_count} high). "
                f"{verified_vulns} findings have verified evidence. "
                f"Immediate remediation required."
            )
        elif has_high:
            v_text = "verified" if verified_vulns > 0 else "reported"
            l_text = f", {likely_vulns} require manual review" if likely_vulns > 0 else ""
            executive = (
                f"{high_count} high-severity {v_text} finding{'s' if high_count > 1 else ''} detected{l_text}. "
                f"Coverage: {coverage['coverage']}% ({coverage['executed']}/{coverage['total']} modules). "
                f"{warning_count} warnings flagged."
            )
        elif has_medium:
            executive = (
                f"{medium_count} medium-severity issues found. "
                f"Coverage: {coverage['coverage']}% ({coverage['executed']}/{coverage['total']} modules). "
                f"{warning_count} warnings. Schedule remediation in next maintenance cycle."
            )
        else:
            executive = (
                f"Scan completed successfully. {safe_count} security checks passed. "
                f"Coverage: {coverage['coverage']}% ({coverage['executed']}/{coverage['total']} modules). "
                f"No vulnerabilities detected."
            )

        return {
            "total": len(self.findings),
            "vulnerabilities": vuln_count,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "safe": safe_count,
            "info": info_count,
            "warning": warning_count,
            "duration": (self.end_time - self.start_time).total_seconds() if self.end_time else 0,
            "requests_sent": self.requests_sent,
            "injection_payloads": self.injection_payloads,
            "headers_tests": self.headers_tests,
            "port_tests": self.port_tests,
            "pages_crawled": self.pages_crawled if self.pages_crawled else self.urls_crawled,
            "risk_score": risk_score,
            "overall_severity": overall['label'],
            "overall_description": overall['description'],
            "overall_color": overall['color'],
            "highest_severity": highest.value if highest else 'none',
            "scanner_version": "1.8.0",
            "report_version": "3.1",
            "coverage_total": coverage['total'],
            "coverage_executed": coverage['executed'],
            "coverage_skipped": coverage['skipped'],
            "coverage_failed": coverage['failed'],
            "coverage_not_applicable": coverage['not_applicable'],
            "coverage_percentage": coverage['coverage'],
            "risk_breakdown": self.calculate_risk_breakdown(),
            # Attack surface
            "urls_discovered": len(self.urls_discovered),
            "urls_crawled": self.urls_crawled if self.urls_crawled else self.pages_crawled,
            "urls_skipped": self.urls_skipped,
            "useful_pages": self.useful_pages,
            "not_useful_pages": self.not_useful_pages,
            "js_discovered_urls": self.js_discovered_urls,
            "api_endpoints": self.api_endpoints[:20],
            "api_count": len(self.api_endpoints),
            "forms_discovered": self.forms_discovered,
            "hidden_inputs": self.hidden_inputs,
            "params_discovered": self.params_discovered,
            "directories_discovered": self.directories_discovered[:20],
            "dir_count": len(self.directories_discovered),
            "interesting_files": self.interesting_files[:20],
            "file_count": len(self.interesting_files),
            "js_files": self.js_files[:20],
            "js_file_count": len(self.js_files),
            "technologies": self.technologies[:20],
            "tech_count": len(self.technologies),
            "cookies_found": self.cookies_found,
            "headers_found": self.headers_found,
            "authentication_pages": self.authentication_pages[:10],
            "admin_pages": self.admin_pages[:10],
            "skip_reasons": coverage.get('skip_reasons', {}),
            "crawler_type": self.crawler_type,
            "executive_summary": executive,
            "verified_vulns": verified_vulns,
            "likely_vulns": likely_vulns,
            "coverage_percentage": coverage['coverage'],
        }