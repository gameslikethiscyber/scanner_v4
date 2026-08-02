"""
Assessment Engine v3.0 — assembles the final Assessment object.

Single owner of the overall severity verdict, the assessment_confidence score,
the v2-compatible ``statistics`` dict, and the per-finding FindingAssessment
rollups. Consumes the other engines (Evidence, Coverage, Risk) and the
Executive Summary Generator; no output interface recomputes scores.

See docs/ENGINE_ARCHITECTURE_V3.md §5.7 and §6.5.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.assessment import (
    Assessment, CoverageReport, FindingAssessment, RiskResult,
)
from core.coverage_engine import CoverageEngine
from core.evidence_engine import EvidenceEngine
from core.executive_summary import ExecutiveSummaryGenerator
from core.finding import EXECUTION_STATE_LABELS, VERIFICATION_LABELS, Severity, Status
from core.risk_engine import RiskEngine

logger = logging.getLogger('SeaScanner.AssessmentEngine')

# Severity tiers, oldest-to-newest order for the verdict scan.
_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)

# v2 vocabulary ('verified'/'likely') plus the v3 'confirmed' status.
VERIFIED_STATUSES = ('confirmed', 'verified', 'likely')
UNVERIFIED_STATUSES = ('possible', 'manual_review', 'unverified')


class AssessmentEngine:
    """Builds the immutable Assessment for a completed ScanResult."""

    # §6.5 assessment-confidence constants.
    SKIPPED_CONFIDENCE_PENALTY = 6
    FAILED_CONFIDENCE_PENALTY = 10
    COVERAGE_QUALITY_FLOOR = 30
    COVERAGE_PENALTY_SCALE = 0.5
    VERIFIED_BONUS = 5
    UNVERIFIED_PENALTY = 10

    VERSION = {
        "scanner_version": "2.0.0",
        "report_version": "3.2",
        "engine_version": "2.0.0",
        "detection_rules_version": "1.5.0",
        "template_version": "3.2",
    }

    INJECTION_MODULES = (
        'SQL Injection', 'XSS Detection', 'LFI Detection',
        'SSRF Detection', 'Open Redirect', 'Host Header Injection', 'SSTI Detection',
    )

    def __init__(self) -> None:
        self.evidence_engine = EvidenceEngine()
        self.coverage_engine = CoverageEngine()
        self.risk_engine = RiskEngine()
        self.summary_generator = ExecutiveSummaryGenerator()

    def build(
        self,
        scan_result: Any,
        target: str = "",
        coverage: Optional[CoverageReport] = None,
        risk: Optional[RiskResult] = None,
        correlation_multipliers: Optional[Dict[str, float]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Assessment:
        """Assemble the final Assessment from a completed ScanResult."""
        coverage = coverage or self.coverage_engine.report(
            scan_result.findings, scan_result.total_modules
        )
        risk = risk or self.risk_engine.calculate(
            scan_result.findings, correlation_multipliers=correlation_multipliers
        )

        verdict = self._overall_verdict(scan_result, risk.risk_score)
        vuln_findings = scan_result.get_vulnerabilities()
        critical_count, high_count, medium_count = self._severity_counts(vuln_findings)
        verified_vulns = sum(1 for f in vuln_findings if f.verification_status == "verified")

        summary = self.summary_generator.generate(
            coverage=coverage,
            overall_tier=verdict.get('tier', 'none'),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            vuln_findings=vuln_findings,
            warning_count=len(scan_result.get_warning_findings()),
            safe_modules=[f.module for f in scan_result.get_safe_findings()],
        )

        confidence, confidence_factors, confidence_explanation = self._assessment_confidence(
            coverage=coverage,
            verified_vulns=verified_vulns,
            unverified_vulns=self._count_unverified(vuln_findings),
        )

        statistics = self._statistics(
            scan_result, coverage, risk, verdict, summary
        )

        findings = [self._finding_assessment(f, risk) for f in scan_result.findings]
        modules = self._modules_rollup(scan_result)

        return Assessment(
            scan_id=self._scan_id(scan_result),
            target=target or self._default_target(scan_result),
            target_host=self._target_host(target),
            start_time=_iso(scan_result.start_time),
            end_time=_iso(scan_result.end_time),
            duration_seconds=self._duration(scan_result),
            overall_score=int(risk.risk_score),
            overall_severity=verdict.get('severity', 'none'),
            overall_tier=verdict.get('tier', 'none'),
            overall_label=verdict.get('label', 'No Risk'),
            overall_description=verdict.get('description', ''),
            overall_color=verdict.get('color', '#2196F3'),
            overall_reasons=list(verdict.get('reasons', [])),
            assessment_confidence=confidence,
            assessment_confidence_factors=confidence_factors,
            assessment_confidence_explanation=confidence_explanation,
            coverage=coverage,
            summary=summary,
            findings=findings,
            modules=modules,
            statistics=statistics,
            metadata=metadata or {},
        )

    # ===== overall severity verdict (v2 get_overall_severity parity) =====

    def _overall_verdict(self, scan_result: Any, risk_score: float) -> Dict[str, Any]:
        critical = scan_result.get_critical()
        high = scan_result.get_high()
        medium = scan_result.get_medium()
        low = scan_result.get_low()

        def verified_count(findings):
            return sum(1 for f in findings if f.verification_status in VERIFIED_STATUSES)

        reasons: List[str] = []
        if len(critical) > 0 and (verified_count(critical) > 0 or risk_score >= 70):
            sev = Severity.CRITICAL
            reasons.append(
                f"{len(critical)} critical finding(s) with verified evidence or "
                f"high risk score ({risk_score:.0f}%)"
            )
        elif len(critical) >= 2:
            sev = Severity.CRITICAL
            reasons.append(f"{len(critical)} critical findings detected")
        elif len(high) >= 2 and (verified_count(high) >= 2 or risk_score >= 50):
            sev = Severity.HIGH
            reasons.append(f"{len(high)} high-severity findings with verified evidence")
        elif len(high) == 1 and verified_count(high) >= 1:
            sev = Severity.HIGH
            reasons.append("A verified high-severity finding was detected")
        elif len(critical) > 0:
            sev = Severity.HIGH
            reasons.append("Critical finding present but not yet verified")
        elif len(high) > 0 and (risk_score >= 40 or any(f.confidence >= 50 for f in high)):
            sev = Severity.HIGH
            reasons.append(
                "High-severity finding with material confidence or elevated risk score"
            )
        elif len(high) > 0:
            sev = Severity.MEDIUM
            reasons.append(
                "High-severity finding pending manual verification "
                "(low confidence or risk score)"
            )
        elif len(medium) >= 2 and risk_score >= 30:
            sev = Severity.MEDIUM
            reasons.append(f"{len(medium)} medium-severity findings with elevated risk score")
        elif len(medium) > 0:
            sev = Severity.MEDIUM
            reasons.append(f"{len(medium)} medium-severity finding(s) detected")
        elif len(low) > 0:
            sev = Severity.LOW
            reasons.append(f"{len(low)} low-severity finding(s) detected")
        else:
            sev = Severity.NONE
            reasons.append("No vulnerabilities detected during the scan")

        severity_map = {
            Severity.CRITICAL: {
                'severity': 'critical', 'tier': 'critical',
                'label': '🔥 Critical Risk',
                'description': 'Immediate action required. Critical vulnerabilities found.',
                'color': '#f44336',
            },
            Severity.HIGH: {
                'severity': 'high', 'tier': 'high',
                'label': '🚨 High Risk',
                'description': 'Urgent action required. High-risk vulnerabilities found.',
                'color': '#FF9800',
            },
            Severity.MEDIUM: {
                'severity': 'medium', 'tier': 'elevated',
                'label': '⚠️ Elevated Risk',
                'description': 'High-severity finding detected, but requires manual verification.',
                'color': '#FFC107',
            },
            Severity.LOW: {
                'severity': 'low', 'tier': 'low',
                'label': '🟡 Low Risk',
                'description': 'Informational. Low-risk findings for best practice improvements.',
                'color': '#4CAF50',
            },
            Severity.NONE: {
                'severity': 'none', 'tier': 'none',
                'label': '✅ No Risk',
                'description': 'System appears secure. No vulnerabilities detected.',
                'color': '#2196F3',
            },
        }
        result = dict(severity_map.get(sev, severity_map[Severity.NONE]))
        result['reasons'] = reasons
        return result

    # ===== assessment confidence (§6.5) =====

    def _assessment_confidence(self, coverage: CoverageReport,
                               verified_vulns: int,
                               unverified_vulns: int) -> tuple:
        factors: Dict[str, int] = {}
        explanation: List[str] = []

        if coverage.skipped > 0:
            factors['skipped_modules'] = -self.SKIPPED_CONFIDENCE_PENALTY
            explanation.append(
                f"{coverage.skipped} module(s) skipped (-{self.SKIPPED_CONFIDENCE_PENALTY})"
            )
        if coverage.failed > 0:
            factors['failed_modules'] = -self.FAILED_CONFIDENCE_PENALTY
            explanation.append(
                f"{coverage.failed} module(s) failed (-{self.FAILED_CONFIDENCE_PENALTY})"
            )

        quality_shortfall = self.COVERAGE_QUALITY_FLOOR - coverage.coverage_quality
        if quality_shortfall > 0:
            penalty = int(round(quality_shortfall * self.COVERAGE_PENALTY_SCALE))
            factors['degraded_coverage'] = -penalty
            explanation.append(
                f"coverage quality {coverage.coverage_quality} below "
                f"{self.COVERAGE_QUALITY_FLOOR} (-{penalty})"
            )

        if verified_vulns > 0:
            factors['verified_evidence'] = self.VERIFIED_BONUS
            explanation.append(
                f"{verified_vulns} verified finding(s) (+{self.VERIFIED_BONUS})"
            )

        if unverified_vulns > 0:
            factors['unverified_findings'] = -self.UNVERIFIED_PENALTY
            explanation.append(
                f"{unverified_vulns} unverified finding(s) (-{self.UNVERIFIED_PENALTY})"
            )

        confidence = 100 + sum(factors.values())
        confidence = max(0, min(100, confidence))

        if explanation:
            explanation_text = "Confidence " + ", ".join(explanation) + "."
        else:
            explanation_text = "Confidence 100: full coverage and no unverified findings."
        return confidence, factors, explanation_text

    @staticmethod
    def _count_unverified(findings: List[Any]) -> int:
        return sum(
            1 for f in findings
            if getattr(f, 'verification_status', 'unverified') in UNVERIFIED_STATUSES
        )

    # ===== statistics dict (v2 get_statistics parity) =====

    def _statistics(self, scan_result: Any, coverage: CoverageReport,
                    risk: RiskResult, verdict: Dict[str, Any],
                    summary: Any) -> Dict[str, Any]:
        vulnerabilities = scan_result.get_vulnerabilities()
        fail_findings = [f for f in scan_result.findings if f.status in (Status.FAIL, Status.VULNERABLE)]
        critical_count, high_count, medium_count, low_count = self._severity_counts(
            fail_findings, include_low=True
        )
        safe_count = len(scan_result.get_safe_findings())
        info_count = len(scan_result.get_info_findings())
        warning_count = len(scan_result.get_warning_findings())
        states = coverage.execution_states or {}
        passed_states = states.get('passed', safe_count)
        na_states = states.get('not_applicable', 0)
        skipped_states = states.get('skipped', 0)

        injection_payloads, headers_tests, port_tests = self._test_counters(scan_result)

        highest = scan_result.get_highest_severity()
        correlation = scan_result.correlation_results or {}

        return {
            "total": len(scan_result.findings),
            "vulnerabilities": len(vulnerabilities),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "safe": safe_count,
            "info": info_count,
            "warning": warning_count,
            "duration": self._duration(scan_result),
            "requests_sent": scan_result.requests_sent,
            "injection_payloads": injection_payloads,
            "headers_tests": headers_tests,
            "port_tests": port_tests,
            "pages_crawled": scan_result.pages_crawled if scan_result.pages_crawled else scan_result.urls_crawled,
            "risk_score": int(risk.risk_score),
            "overall_severity": verdict['label'],
            "overall_description": verdict['description'],
            "overall_color": verdict['color'],
            "overall_tier": verdict.get('tier', 'none'),
            "overall_reasons": verdict.get('reasons', []),
            "highest_severity": highest.value if highest else 'none',
            **self.VERSION,
            "coverage_total": coverage.total,
            "coverage_executed": coverage.executed,
            "coverage_skipped": coverage.skipped,
            "coverage_failed": coverage.failed,
            "coverage_not_applicable": coverage.not_applicable,
            "coverage_percentage": coverage.coverage_percent,
            "coverage_explanation": coverage.explanation,
            "execution_states": states,
            "payload_testing": scan_result.get_payload_testing_status(),
            "labels": {
                "verification": VERIFICATION_LABELS,
                "execution_state": {
                    (k.value if hasattr(k, 'value') else k): v
                    for k, v in EXECUTION_STATE_LABELS.items()
                },
            },
            "risk_breakdown": self._risk_breakdown_dict(risk),
            "urls_discovered": len(scan_result.urls_discovered),
            "urls_crawled": scan_result.urls_crawled if scan_result.urls_crawled else scan_result.pages_crawled,
            "urls_skipped": scan_result.urls_skipped,
            "useful_pages": scan_result.useful_pages,
            "not_useful_pages": scan_result.not_useful_pages,
            "js_discovered_urls": scan_result.js_discovered_urls,
            "api_endpoints": scan_result.api_endpoints[:20],
            "api_count": len(scan_result.api_endpoints),
            "forms_discovered": scan_result.forms_discovered,
            "hidden_inputs": scan_result.hidden_inputs,
            "params_discovered": scan_result.params_discovered,
            "directories_discovered": scan_result.directories_discovered[:20],
            "dir_count": len(scan_result.directories_discovered),
            "interesting_files": scan_result.interesting_files[:20],
            "file_count": len(scan_result.interesting_files),
            "js_files": scan_result.js_files[:20],
            "js_file_count": len(scan_result.js_files),
            "technologies": scan_result.technologies[:20],
            "tech_count": len(scan_result.technologies),
            "cookies_found": scan_result.cookies_found,
            "headers_found": scan_result.headers_found,
            "authentication_pages": scan_result.authentication_pages[:10],
            "admin_pages": scan_result.admin_pages[:10],
            "skip_reasons": coverage.skip_reasons,
            "crawler_type": scan_result.crawler_type,
            "executive_summary": summary.prose,
            "verified_vulns": summary.verified_count,
            "likely_vulns": summary.likely_count,
            "coverage_percentage": coverage.coverage_percent,
            "correlations_found": correlation.get('correlations_found', 0),
            "correlation_details": correlation.get('details', []),
            "auth": self._auth_stats(scan_result),
        }

    def _auth_stats(self, scan_result: Any) -> Dict[str, Any]:
        return scan_result._auth_stats()

    @staticmethod
    def _test_counters(scan_result: Any) -> tuple:
        injection_payloads = 0
        headers_tests = 0
        port_tests = 0
        for f in scan_result.findings:
            if f.module in ('SQL Injection', 'XSS Detection', 'LFI Detection',
                            'SSRF Detection', 'Open Redirect', 'Host Header Injection'):
                injection_payloads += f.tests_performed
            elif f.module == 'Headers Security':
                headers_tests += f.tests_performed
            elif f.module == 'Open Ports':
                port_tests += f.tests_performed
        return injection_payloads, headers_tests, port_tests

    @staticmethod
    def _risk_breakdown_dict(risk: RiskResult) -> Dict[str, Any]:
        return {
            "risk_score": risk.risk_score,
            "security_grade": risk.security_grade,
            "total_weighted": risk.total_weighted,
            "max_possible": risk.max_possible,
            "breakdown": risk.breakdown,
            "explanation": risk.explanation,
            "summary": risk.summary,
            "vulnerability_count": risk.vulnerability_count,
            "warning_count": risk.warning_count,
            "calculation_formula": risk.calculation_formula,
        }

    # ===== per-finding and module rollups =====

    def _finding_assessment(self, f: Any, risk: RiskResult) -> FindingAssessment:
        state = self._execution_state(f)
        evidence_quality = self.evidence_engine.score(f.evidence).evidence_quality
        contribution = next(
            (b.get('score', 0.0) for b in risk.breakdown if b.get('module') == f.module),
            0.0,
        )
        return FindingAssessment(
            module=f.module,
            title=f.title or f.module,
            status=f.status.value,
            execution_state=state.value,
            execution_reason=f.state_reason or f.reason or '',
            severity=f.severity.value,
            confidence=f.confidence,
            confidence_factors=dict(f.confidence_factors or {}),
            confidence_explanation=f.confidence_explanation or '',
            verification=getattr(f, 'verification_class', '') or f.verification_status or 'unverified',
            evidence_quality=evidence_quality,
            cvss_score=f.cvss_score,
            cvss_vector=f.cvss_vector or '',
            cvss_explanation=f.cvss_explanation or '',
            exploitability=_enum_value(getattr(f, 'exploitability', 'unknown')),
            impact=dict(f.impact or {}),
            cwe_id=f.cwe_id or '',
            owasp_category=f.owasp_category or '',
            capec_id=f.capec_id or '',
            mitre_id=f.mitre_id or '',
            asvs_reference=f.asvs_reference or '',
            evidence=[self._evidence_dict(e) for e in f.evidence],
            recommendations=list(f.recommendations or []),
            references=list(f.references or []),
            risk_contribution=float(contribution),
            timestamps={'detected': f.timestamp or ''},
        )

    @staticmethod
    def _evidence_dict(e: Any) -> Dict[str, Any]:
        if hasattr(e, 'to_dict'):
            return e.to_dict()
        if isinstance(e, dict):
            return e
        return {'description': str(e)}

    def _modules_rollup(self, scan_result: Any) -> Dict[str, Dict[str, Any]]:
        modules: Dict[str, Dict[str, Any]] = {}
        for f in scan_result.findings:
            state = self._execution_state(f)
            modules[f.module] = {
                'state': state.value,
                'label': EXECUTION_STATE_LABELS.get(state, state.value),
                'severity': f.severity.value,
                'confidence': f.confidence,
                'verification': f.verification_status or 'unverified',
                'reason': f.state_reason or f.reason or '',
            }
        return modules

    @staticmethod
    def _execution_state(f: Any) -> Any:
        """Engine-owned execution state (set by the pipeline via CoverageEngine).

        Falls back to the Coverage Engine when the finding has not been pipelined
        (direct AssessmentEngine.build() consumers). The Coverage Engine is the
        single owner of execution-state classification.
        """
        if getattr(f, 'execution_state', None) is not None:
            return f.execution_state
        return CoverageEngine.classify_execution_state(f)[0]

    # ===== scan identity =====

    @staticmethod
    def _severity_counts(findings: List[Any], include_low: bool = False) -> tuple:
        counts = {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
        for f in findings:
            sev = f.severity
            if sev in counts:
                counts[sev] += 1
        if include_low:
            return (counts[Severity.CRITICAL], counts[Severity.HIGH],
                    counts[Severity.MEDIUM], counts[Severity.LOW])
        return (counts[Severity.CRITICAL], counts[Severity.HIGH], counts[Severity.MEDIUM])

    @staticmethod
    def _duration(scan_result: Any) -> float:
        if not scan_result.end_time:
            return 0.0
        return (scan_result.end_time - scan_result.start_time).total_seconds()

    @staticmethod
    def _scan_id(scan_result: Any) -> str:
        stamp = scan_result.start_time or datetime.now()
        return f"scan_{stamp:%Y%m%d_%H%M%S}"

    @staticmethod
    def _default_target(scan_result: Any) -> str:
        for f in scan_result.findings:
            if getattr(f, 'target', ''):
                return f.target
        return ""

    @staticmethod
    def _target_host(target: str) -> str:
        if not target:
            return ""
        parsed = urlparse(target if '://' in target else f"//{target}")
        return parsed.hostname or target


def _iso(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    if isinstance(dt, str):
        return dt
    return dt.isoformat()


def _enum_value(value: Any) -> str:
    if value is None:
        return 'unknown'
    if hasattr(value, 'value'):
        return value.value
    return str(value)
