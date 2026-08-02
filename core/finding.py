"""
Unified Finding Structure - v3.1 (Full)
"""

from enum import Enum
from datetime import datetime
from typing import Optional, List, Dict, Any
from threading import Lock
from core.evidence import EvidenceLevel
from core.auth_manager import AUTH_STATE_LABELS, AUTH_METHOD_LABELS

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
    MEDIUM = "hard" if False else "medium"
    HARD = "hard"
    THEORETICAL = "theoretical"
    UNKNOWN = "unknown"

class ExecutionState(Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"
    WARNING = "warning"
    INFO = "info"
    AUTH_REQUIRED = "auth_required"
    AUTHENTICATED = "authenticated"
    PUBLIC_ONLY = "public_only"
    SESSION_EXPIRED = "session_expired"
    LOGIN_FAILED = "login_failed"
    TOKEN_INVALID = "token_invalid"

VERIFICATION_LABELS = {
    'verified': 'Verified',
    'likely': 'Likely',
    'possible': 'Possible',
    'manual_review': 'Manual Review',
    'unverified': 'Unverified',
}

EXECUTION_STATE_LABELS = {
    ExecutionState.PASSED: 'Passed',
    ExecutionState.FAILED: 'Failed',
    ExecutionState.SKIPPED: 'Skipped',
    ExecutionState.NOT_APPLICABLE: 'Not Applicable',
    ExecutionState.WARNING: 'Warning',
    ExecutionState.INFO: 'Info',
    ExecutionState.AUTH_REQUIRED: 'Auth Required',
    ExecutionState.AUTHENTICATED: 'Authenticated',
    ExecutionState.PUBLIC_ONLY: 'Public Only',
    ExecutionState.SESSION_EXPIRED: 'Session Expired',
    ExecutionState.LOGIN_FAILED: 'Login Failed',
    ExecutionState.TOKEN_INVALID: 'Token Invalid',
}

POSITIVE_OBSERVATION_TERMS = (
    'supported', 'present', 'enabled', 'configured', 'disabled',
    'passed', 'no vulnerability', 'not vulnerable', 'secure',
    'properly set', 'properly configured', 'found to be safe',
    'no issues detected', 'compliant', 'correctly configured',
)

class Finding:
    """One module's result.

    Field ownership (single-writer rule — engines are the only assessment writers):

    SCANNER-OWNED  (populated by ``scanners/*.scan()``; engines never touch them):
      id, module, title, description, evidence, requests_made, responses_received,
      recommendations, references, fingerprint, conditions, raw_data, duration,
      tests_performed, tests_run, tests_passed, scan_errors, timeout, target,
      payload_evidence, response_fingerprint, baseline_fingerprint,
      technical_explanation, remediation_steps, occurrences, affected_urls,
      details, detection_methods, timestamp, verify_commands (populated by the
      legacy decide() path only), replay_data (same), cross_validated (may be set
      by scanner verification passes).

    ENGINE-OWNED  (written by the v3 pipeline / legacy decide(); scanners must NOT
      set these on migrated scanners — they are the "assessment result"):
      status, severity, exploitability, impact, cvss_score, cvss_vector,
      cvss_explanation, confidence, confidence_factors, confidence_explanation,
      verification_status, verification_class, verification_passes, matched_rules,
      execution_state, state_reason, reason, recommendation, evidence_quality,
      correlation_escalated, correlation_findings, cwe_id, owasp_category,
      capec_id, mitre_id, asvs_reference, security_grade, risk_level.

    LEGACY / v2-COMPAT  (temporary; removed after the A8 migration, see
      docs/TECHNICAL_DEBT.md):
      module_name, findings, tests_run, confirmations, heuristics,
      false_positive_risk, evidence_text, skipped, skip_reason, meta,
      duration_ms, verify_commands, replay_data, security_grade, risk_level.

    v3 VERIFICATION VOCABULARY: ``verification_status`` holds the report
    vocabulary (verified/likely/possible/manual_review/unverified — v2 parity);
    ``verification_class`` holds the raw v3 band (confirmed/likely/possible/
    manual_review/unverified). ``verification_label`` renders the report label.

    A8.9 FREEZE: ``add_evidence()`` only records evidence. All assessment fields
    (status/severity/confidence/verification/execution-state) are written by the
    v3 engine pipeline. The archived v2 side effect lives in tests/v2_reference.py.
    """

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

        # Correlation fields
        self.correlation_escalated: bool = False
        self.correlation_findings: List[str] = []
        self.cross_validated: bool = False
        self.verification_passes: int = 0
        self.payload_evidence: List[str] = []
        self.response_fingerprint: str = ""
        self.baseline_fingerprint: str = ""
        self.technical_explanation: str = ""
        self.owasp_mapping: str = ""
        self.cwe_mapping: str = ""
        self.remediation_steps: List[str] = []

        # SOP report-accuracy fields
        self.execution_state: Optional[ExecutionState] = None
        self.state_reason: str = ""
        self.confidence_explanation: str = ""
        self.matched_rules: List[str] = []

        # v3 verification vocabulary (internal 'confirmed' vs report 'verified').
        self.verification_class: str = "unverified"

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
        for r in other.matched_rules:
            if r not in self.matched_rules:
                self.matched_rules.append(r)
        self.state_reason = self.state_reason or other.state_reason
        if other.confidence_explanation and not self.confidence_explanation:
            self.confidence_explanation = other.confidence_explanation

    def is_skipped(self) -> bool:
        return self.skipped or self.status == Status.SKIPPED

    def is_safe(self) -> bool:
        return self.status == Status.SAFE or self.status == Status.PASS

    def is_vulnerable(self) -> bool:
        return self.status == Status.VULNERABLE or self.status == Status.FAIL

    def add_evidence(self, evidence: Any) -> None:
        self.evidence.append(evidence)

    @property
    def verification_label(self) -> str:
        return VERIFICATION_LABELS.get(self.verification_status, self.verification_status)

    @property
    def execution_label(self) -> str:
        if self.execution_state is None:
            from core.coverage_engine import CoverageEngine
            self.execution_state, self.state_reason = CoverageEngine.classify_execution_state(self)
        return EXECUTION_STATE_LABELS.get(self.execution_state, self.execution_state.value)

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
            "correlation_escalated": self.correlation_escalated,
            "correlation_findings": self.correlation_findings,
            "cross_validated": self.cross_validated,
            "verification_passes": self.verification_passes,
            "payload_evidence": self.payload_evidence,
            "response_fingerprint": self.response_fingerprint,
            "baseline_fingerprint": self.baseline_fingerprint,
            "technical_explanation": self.technical_explanation,
            "owasp_mapping": self.owasp_mapping,
            "cwe_mapping": self.cwe_mapping,
            "remediation_steps": self.remediation_steps,
            "execution_state": self.execution_state.value if self.execution_state else None,
            "state_reason": self.state_reason,
            "confidence_explanation": self.confidence_explanation,
            "matched_rules": self.matched_rules,
            "verification_label": self.verification_label,
            "execution_label": self.execution_label,
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
        # Single assessment output (Phase A9): set once by run_assessment_pipeline().
        # Every consumer (reporters, GUI, CLI, backend) reads this object only; the
        # legacy assessment methods below delegate to it when it is present and fall
        # back to inline computation only for un-assessed (raw) ScanResults.
        self.assessment: Optional["Assessment"] = None

        # Attack surface inventory
        self.urls_discovered: List[str] = []
        self.urls_crawled: int = 0
        self.urls_skipped: int = 0
        self.useful_pages: int = 0
        self.not_useful_pages: int = 0
        self.js_discovered_urls: int = 0
        self.api_endpoints: List[str] = []
        self.correlation_results: Dict[str, Any] = {'correlations_found': 0, 'details': []}
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

        # Authentication awareness (optional; never affects public scans)
        self.auth_detected: bool = False
        self.auth_confidence: int = 0
        self.auth_reasons: List[str] = []
        self.auth_framework: str = ""
        self.auth_method: str = "public"
        self.auth_state: str = "none"
        self.auth_state_label: str = "No Authentication"
        self.auth_session: Optional[Any] = None
        self.auth_accessible: int = 0
        self.auth_blocked: int = 0
        self.auth_redirected: int = 0
        self.auth_unauthorized: int = 0
        self.auth_unknown: int = 0
        self.auth_public_pages: int = 0
        self.auth_authenticated_pages: int = 0
        self.auth_protected_areas: List[str] = []
        self.auth_coverage_public: int = 0
        self.auth_coverage_authenticated: int = 0
        self.auth_coverage_overall: int = 0
        self.auth_coverage_improvement: int = 0
        self.auth_est_improvement: int = 0
        self.auth_session_checked: bool = False
        self.auth_session_valid: bool = True

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

    def assess(self, **kwargs) -> "Assessment":
        """Run the single assessment pipeline and return the immutable Assessment.

        ``run_assessment_pipeline`` (core.pipeline) applies Evidence → Confidence →
        Verification → Severity per finding, then correlation, Risk, Coverage and
        the Assessment Engine. The resulting Assessment is stored on
        ``self.assessment`` (idempotent) and becomes the only data source every
        consumer reads. ``kwargs`` are forwarded to the pipeline (e.g. ``metadata``).
        """
        from core.pipeline import run_assessment_pipeline
        if self.assessment is None:
            self.assessment = run_assessment_pipeline(self, **kwargs)
        return self.assessment

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

    def get_execution_states(self) -> Dict[str, Any]:
        if self.assessment is not None:
            return dict(self.assessment.coverage.execution_states or {})
        counts = {
            ExecutionState.PASSED: 0,
            ExecutionState.FAILED: 0,
            ExecutionState.SKIPPED: 0,
            ExecutionState.NOT_APPLICABLE: 0,
            ExecutionState.WARNING: 0,
            ExecutionState.INFO: 0,
            ExecutionState.AUTH_REQUIRED: 0,
            ExecutionState.AUTHENTICATED: 0,
            ExecutionState.PUBLIC_ONLY: 0,
            ExecutionState.SESSION_EXPIRED: 0,
            ExecutionState.LOGIN_FAILED: 0,
            ExecutionState.TOKEN_INVALID: 0,
        }
        details = []
        for f in self.findings:
            state = f.execution_state
            reason = f.state_reason or f.reason or ''
            if state is None:
                from core.coverage_engine import CoverageEngine
                state, state_reason = CoverageEngine.classify_execution_state(f)
                f.execution_state = state
                f.state_reason = state_reason
                reason = state_reason or f.reason or ''
            counts[state] += 1
            details.append({
                'module': f.module,
                'state': state.value,
                'label': EXECUTION_STATE_LABELS.get(state, state.value),
                'reason': reason,
                'tests': f.tests_performed,
                'duration': f.duration,
            })

        executed = (counts[ExecutionState.PASSED] + counts[ExecutionState.FAILED]
                    + counts[ExecutionState.WARNING] + counts[ExecutionState.INFO])

        explanation_parts = []
        if counts[ExecutionState.SKIPPED]:
            skipped_names = [d['module'] for d in details if d['state'] == 'skipped']
            explanation_parts.append(
                f"{counts[ExecutionState.SKIPPED]} module(s) skipped "
                f"({', '.join(skipped_names[:5])})"
            )
        if counts[ExecutionState.NOT_APPLICABLE]:
            na_names = [d['module'] for d in details if d['state'] == 'not_applicable']
            explanation_parts.append(
                f"{counts[ExecutionState.NOT_APPLICABLE]} module(s) not applicable "
                f"({', '.join(na_names[:5])})"
            )
        if counts[ExecutionState.FAILED]:
            explanation_parts.append(f"{counts[ExecutionState.FAILED]} module(s) failed")

        if explanation_parts:
            explanation = "Coverage reduced because " + "; ".join(explanation_parts) + "."
        else:
            explanation = "All modules executed successfully; coverage reflects full scan."

        return {
            'passed': counts[ExecutionState.PASSED],
            'failed': counts[ExecutionState.FAILED],
            'skipped': counts[ExecutionState.SKIPPED],
            'not_applicable': counts[ExecutionState.NOT_APPLICABLE],
            'warning': counts[ExecutionState.WARNING],
            'info': counts[ExecutionState.INFO],
            'auth_required': counts[ExecutionState.AUTH_REQUIRED],
            'authenticated': counts[ExecutionState.AUTHENTICATED],
            'public_only': counts[ExecutionState.PUBLIC_ONLY],
            'session_expired': counts[ExecutionState.SESSION_EXPIRED],
            'login_failed': counts[ExecutionState.LOGIN_FAILED],
            'token_invalid': counts[ExecutionState.TOKEN_INVALID],
            'executed': executed,
            'total': len(self.findings),
            'details': details,
            'explanation': explanation,
        }

    def get_payload_testing_status(self) -> Dict[str, Any]:
        self._aggregate_test_counters()
        count = self.injection_payloads
        if count > 0:
            return {
                'count': count,
                'display': str(count),
                'status': 'executed',
                'reason': "Payloads were executed against discovered parameters and forms.",
            }

        reasons = []
        injection_modules = (
            'SQL Injection', 'XSS Detection', 'LFI Detection', 'SSRF Detection',
            'Open Redirect', 'Host Header Injection', 'SSTI Detection',
        )
        for f in self.findings:
            if f.module not in injection_modules or f.is_vulnerable():
                continue
            if f.is_skipped() and f.skip_reason:
                r = (f.skip_reason or '').strip()
                if r and r not in reasons:
                    reasons.append(r)
            elif f.tests_performed == 0 and f.reason:
                r = (f.reason or '').strip()
                if r and r not in reasons:
                    reasons.append(r)

        if reasons:
            reason_text = '; '.join(reasons[:3])
        else:
            reason_text = "No injectable parameters or forms were discovered, so no payloads were tested."
        return {
            'count': 0,
            'display': 'Skipped',
            'status': 'skipped',
            'reason': reason_text,
        }

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
        if self.assessment is not None:
            c = self.assessment.coverage
            return {
                'total': c.total,
                'executed': c.executed,
                'skipped': c.skipped,
                'failed': c.failed,
                'not_applicable': c.not_applicable,
                'coverage': c.coverage_percent,
                'skip_reasons': dict(c.skip_reasons),
                'explanation': c.explanation,
                'states': dict(c.execution_states or {}),
            }
        states = self.get_execution_states()
        executed = states['executed']
        skipped = states['skipped']
        failed = states['failed']
        not_applicable = states['not_applicable']

        total = self.total_modules
        if total <= 0:
            total = len(self.findings)
        coverage = int((executed / total) * 100) if total > 0 else 0

        # Build per-module skip/na reasons
        skip_reasons = {}
        for d in states['details']:
            if d['state'] in ('skipped', 'not_applicable') and d['reason']:
                key = d['reason'][:60]
                if key not in skip_reasons:
                    skip_reasons[key] = []
                skip_reasons[key].append(d['module'])

        return {
            'total': total,
            'executed': executed,
            'skipped': skipped,
            'failed': failed,
            'not_applicable': not_applicable,
            'coverage': coverage,
            'skip_reasons': skip_reasons,
            'explanation': states['explanation'],
            'states': states,
        }

    def run_correlation(self):
        if self.assessment is not None:
            # Correlation is owned by the assessment pipeline; findings are already
            # boosted/escalated and correlation_results is already populated.
            return []
        from core.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        results = engine.correlate(self.findings)
        self.correlation_results = engine.get_correlation_summary()
        return results

    # ===== Authentication awareness =====

    def set_auth_detection(self, detection) -> None:
        """Record an AuthDetectionResult (or dict) from the detection phase."""
        if detection is None:
            return
        if hasattr(detection, 'to_dict'):
            d = detection.to_dict()
        elif isinstance(detection, dict):
            d = detection
        else:
            return
        self.auth_detected = bool(d.get('detected'))
        self.auth_confidence = int(d.get('confidence', 0))
        self.auth_reasons = list(d.get('reasons', []))
        self.auth_framework = str(d.get('framework', '') or '')

    def set_auth_session(self, auth_session) -> None:
        """Attach an AuthSession; its state becomes the scan's auth state."""
        self.auth_session = auth_session
        if auth_session is None:
            self.auth_method = "public"
            self.auth_state = "none"
            self.auth_state_label = "No Authentication"
            return
        self.auth_method = getattr(auth_session, 'method', 'public') or 'public'
        state = getattr(auth_session, 'state', None)
        if state is not None and hasattr(state, 'value'):
            self.auth_state = state.value
            self.auth_state_label = AUTH_STATE_LABELS.get(state, state.value)
        else:
            self.auth_state = str(state or 'public_only')
            self.auth_state_label = self.auth_state

    def record_auth_response(self, classification: Dict[str, Any]) -> None:
        """Accumulate a classified response (from classify_auth_response).

        ``auth_public_pages`` / ``auth_authenticated_pages`` are distinct page
        counts maintained by the crawler, so accessible responses here only
        update ``auth_accessible``.
        """
        c = (classification or {}).get('classification', 'unknown')
        if c == 'accessible':
            self.auth_accessible += 1
        elif c == 'blocked':
            self.auth_blocked += 1
        elif c == 'redirected':
            self.auth_redirected += 1
        elif c == 'unauthorized':
            self.auth_unauthorized += 1
        else:
            self.auth_unknown += 1

    def evaluate_auth_state(self) -> str:
        """Post-scan heuristic: detect expired / invalid authenticated sessions."""
        if self.auth_session is None:
            return self.auth_state
        if self.auth_session.state.value in ('session_expired', 'login_failed', 'token_invalid'):
            self.auth_state = self.auth_session.state.value
            self.auth_state_label = AUTH_STATE_LABELS.get(self.auth_session.state, self.auth_session.state.value)
            return self.auth_state
        protected = self.auth_blocked + self.auth_unauthorized + self.auth_redirected
        if self.auth_method in ('cookies', 'login', 'browser') and protected > 0 and self.auth_authenticated_pages == 0:
            self.auth_session.mark_expired()
        elif self.auth_method in ('bearer', 'jwt', 'headers') and self.auth_unauthorized > 0 and self.auth_authenticated_pages == 0:
            self.auth_session.mark_token_invalid()
        if self.auth_session.state.value != 'authenticated':
            self.auth_state = self.auth_session.state.value
            self.auth_state_label = AUTH_STATE_LABELS.get(self.auth_session.state, self.auth_session.state.value)
        return self.auth_state

    def get_auth_coverage(self) -> Dict[str, Any]:
        """Phase 10: distinguish public / authenticated / blocked / unknown coverage."""
        total = (self.auth_public_pages + self.auth_authenticated_pages
                 + self.auth_blocked + self.auth_redirected
                 + self.auth_unauthorized + self.auth_unknown)
        public = int((self.auth_public_pages / total) * 100) if total else 100
        authenticated = int(
            ((self.auth_public_pages + self.auth_authenticated_pages) / total) * 100
        ) if total else 100
        blocked = int(((self.auth_blocked + self.auth_redirected + self.auth_unauthorized) / total) * 100) if total else 0
        unknown = int((self.auth_unknown / total) * 100) if total else 0

        self.auth_coverage_public = public
        self.auth_coverage_authenticated = authenticated
        self.auth_coverage_overall = authenticated if self.auth_session and self.auth_session.is_authenticated() else public
        if self.auth_coverage_authenticated > self.auth_coverage_public:
            self.auth_coverage_improvement = self.auth_coverage_authenticated - self.auth_coverage_public
        else:
            self.auth_coverage_improvement = self.auth_est_improvement

        return {
            'total': total,
            'public_pages': self.auth_public_pages,
            'authenticated_pages': self.auth_authenticated_pages,
            'blocked_pages': self.auth_blocked,
            'redirected_pages': self.auth_redirected,
            'unauthorized_pages': self.auth_unauthorized,
            'unknown_pages': self.auth_unknown,
            'public': public,
            'authenticated': authenticated,
            'blocked': blocked,
            'unknown': unknown,
            'overall': self.auth_coverage_overall,
            'improvement': self.auth_coverage_improvement,
            'protected_areas': self.auth_protected_areas,
        }

    def _auth_stats(self) -> Dict[str, Any]:
        """Redacted, report-safe authentication summary (Phase 9 / 10 / 11)."""
        coverage = self.get_auth_coverage()
        session = self.auth_session.to_dict(redact=True) if self.auth_session is not None else None
        state = self.auth_state
        if self.auth_session is not None and self.auth_session.state is not None:
            state = self.auth_session.state.value
            self.auth_state_label = AUTH_STATE_LABELS.get(self.auth_session.state, self.auth_session.state.value)
        return {
            'detected': self.auth_detected,
            'confidence': self.auth_confidence,
            'reasons': self.auth_reasons[:8],
            'framework': self.auth_framework,
            'method': self.auth_method,
            'method_label': AUTH_METHOD_LABELS.get(self.auth_method, self.auth_method),
            'state': state,
            'state_label': self.auth_state_label,
            'authenticated': self.auth_session is not None and state == 'authenticated',
            'mode': AUTH_METHOD_LABELS.get(self.auth_method, self.auth_method),
            'session_valid': self.auth_session_valid,
            'session_checked': self.auth_session_checked,
            'coverage': coverage,
            'session': session,
        }

    def _aggregate_test_counters(self):
        """Aggregate injection_payloads, headers_tests, and port_tests from findings."""
        self.injection_payloads = 0
        self.headers_tests = 0
        self.port_tests = 0
        for f in self.findings:
            if f.module in ('SQL Injection', 'XSS Detection', 'LFI Detection',
                            'SSRF Detection', 'Open Redirect', 'Host Header Injection'):
                self.injection_payloads += f.tests_performed
            elif f.module == 'Headers Security':
                self.headers_tests += f.tests_performed
            elif f.module == 'Open Ports':
                self.port_tests += f.tests_performed

    def calculate_dynamic_risk_score(self) -> int:
        if self.assessment is not None:
            return int(self.assessment.statistics.get('risk_score', 0))
        from core.decision_engine import RiskCalculator
        result = RiskCalculator.calculate(self.findings)
        return int(result["risk_score"])

    def calculate_risk_breakdown(self) -> Dict[str, Any]:
        if self.assessment is not None:
            return dict(self.assessment.statistics.get('risk_breakdown', {}) or {})
        from core.decision_engine import RiskCalculator
        return RiskCalculator.calculate(self.findings)

    def get_overall_severity(self) -> Dict[str, Any]:
        if self.assessment is not None:
            a = self.assessment
            return {
                'tier': a.overall_tier,
                'label': a.overall_label,
                'description': a.overall_description,
                'color': a.overall_color,
                'reasons': list(a.overall_reasons),
            }
        critical = self.get_critical()
        high = self.get_high()
        medium = self.get_medium()
        low = self.get_low()
        risk_score = self.calculate_dynamic_risk_score()

        def verified_count(findings):
            return sum(1 for f in findings if f.verification_status in ('verified', 'likely'))

        reasons = []

        # Multi-factor policy (never severity from numeric score alone):
        # - CRITICAL: any verified critical finding, or 2+ critical findings, or
        #   a risk score >= 70 together with critical findings present.
        # - HIGH: a verified high finding, or 2+ high findings, or a risk score
        #   >= 40 with material confidence, or an unverified critical finding.
        # - MEDIUM/ELEVATED: any medium finding, an unverified high finding, or
        #   a high-risk score with medium findings present.
        # - LOW: low-severity findings only.
        # - NONE: no vulnerabilities.
        if len(critical) > 0 and (verified_count(critical) > 0 or risk_score >= 70):
            sev = Severity.CRITICAL
            reasons.append(
                f"{len(critical)} critical finding(s) with verified evidence or "
                f"high risk score ({risk_score}%)"
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
                'tier': 'critical',
                'label': '🔥 Critical Risk',
                'description': 'Immediate action required. Critical vulnerabilities found.',
                'color': '#f44336'
            },
            Severity.HIGH: {
                'tier': 'high',
                'label': '🚨 High Risk',
                'description': 'Urgent action required. High-risk vulnerabilities found.',
                'color': '#FF9800'
            },
            Severity.MEDIUM: {
                'tier': 'elevated',
                'label': '⚠️ Elevated Risk',
                'description': 'High-severity finding detected, but requires manual verification.',
                'color': '#FFC107'
            },
            Severity.LOW: {
                'tier': 'low',
                'label': '🟡 Low Risk',
                'description': 'Informational. Low-risk findings for best practice improvements.',
                'color': '#4CAF50'
            },
            Severity.NONE: {
                'tier': 'none',
                'label': '✅ No Risk',
                'description': 'System appears secure. No vulnerabilities detected.',
                'color': '#2196F3'
            }
        }
        result = severity_map.get(sev, severity_map[Severity.NONE])
        result['reasons'] = reasons
        return result

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

        # SOP #14: overall severity must be consistent with the highest finding.
        overall = self.get_overall_severity()
        tier = overall.get('tier', 'none')
        highest = self.get_highest_severity()
        if highest == Severity.CRITICAL and tier not in ('critical', 'high'):
            errors.append("Overall severity is inconsistent with critical findings")
        elif highest == Severity.HIGH and tier not in ('critical', 'high', 'elevated'):
            errors.append("Overall severity is inconsistent with high findings")
        elif highest == Severity.MEDIUM and tier == 'none':
            errors.append("Overall severity is inconsistent with medium findings")

        # SOP #14: coverage counts must reconcile with executed scanners.
        coverage = self.get_coverage()
        total = coverage.get('total', 0)
        if total > 0:
            parts = (coverage.get('executed', 0) + coverage.get('skipped', 0)
                     + coverage.get('not_applicable', 0))
            if parts != total:
                errors.append(
                    f"Coverage counts do not reconcile "
                    f"(executed+skipped+na={parts}, total={total})"
                )

        # SOP #14: skipped count must match skipped findings.
        if coverage.get('skipped', 0) != len(self.get_skipped_findings()):
            errors.append("Skipped count does not match skipped findings")

        # SOP #14: no positive observation may be reported under warnings.
        for f in self.get_warning_findings():
            first_ev = getattr(f.evidence[0], 'description', '') if f.evidence else ''
            text = " ".join([f.reason or '', f.description or '', first_ev]).lower()
            if any(term in text for term in POSITIVE_OBSERVATION_TERMS):
                errors.append(
                    f"Warning '{f.module}' contains a positive observation "
                    "and should be reclassified as Passed or Informational"
                )

        # SOP #14: every finding must carry evidence, confidence, recommendation,
        # verification state and reasoning before it is reported.
        for f in self.findings:
            if f.is_vulnerable():
                if not f.evidence and not f.evidence_text:
                    errors.append(f"Finding '{f.module}' has no evidence")
                if not f.reason:
                    errors.append(f"Finding '{f.module}' has no decision reason")
                if not f.recommendation:
                    errors.append(f"Finding '{f.module}' has no recommendation")
                if not f.verification_status:
                    errors.append(f"Finding '{f.module}' has no verification status")
                if f.confidence <= 0:
                    errors.append(f"Finding '{f.module}' has no confidence")
            elif f.status in (Status.WARNING, Status.INFO) and not f.reason:
                errors.append(f"Finding '{f.module}' has no decision reason")
            elif f.is_safe() and not f.reason:
                errors.append(f"Finding '{f.module}' is marked passed without a reason")
        return errors

    def get_statistics(self) -> Dict[str, Any]:
        if self.assessment is not None:
            return dict(self.assessment.statistics or {})
        self._aggregate_test_counters()
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
        states = coverage.get('states', {})
        passed_states = states.get('passed', safe_count)
        na_states = states.get('not_applicable', 0)
        skipped_states = states.get('skipped', 0)

        skipped_count = coverage.get('skipped', 0)
        coverage_note = ""
        if skipped_count > 0 or na_states > 0:
            coverage_note = f" Coverage was reduced because {skipped_count} module(s) were skipped and {na_states} were not applicable to this target."

        if has_critical:
            executive = (
                f"Critical vulnerabilities were detected: {critical_count} critical and "
                f"{high_count} high-severity finding(s). {verified_vulns} finding(s) have "
                f"verified evidence; immediate remediation is required. "
                f"Coverage reached {coverage['coverage']}% "
                f"({coverage['executed']}/{coverage['total']} modules executed)."
            )
        elif has_high:
            v_text = "verified" if verified_vulns > 0 else "reported"
            l_text = f" {likely_vulns} finding(s) require manual review." if likely_vulns > 0 else ""
            executive = (
                f"{high_count} high-severity {v_text} finding(s) were detected.{l_text} "
                f"Coverage reached {coverage['coverage']}% "
                f"({coverage['executed']}/{coverage['total']} modules executed), "
                f"with {warning_count} warning(s) flagged.{coverage_note}"
            )
        elif has_medium:
            executive = (
                f"{medium_count} medium-severity issue(s) were found. "
                f"Coverage reached {coverage['coverage']}% "
                f"({coverage['executed']}/{coverage['total']} modules executed), "
                f"with {warning_count} warning(s). Remediation should be scheduled "
                f"in the next maintenance cycle.{coverage_note}"
            )
        else:
            executive = (
                f"The scan completed successfully: {passed_states} security check(s) passed "
                f"and no vulnerabilities were detected. "
                f"Coverage reached {coverage['coverage']}% "
                f"({coverage['executed']}/{coverage['total']} modules executed)."
                f"{coverage_note}"
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
            "overall_tier": overall.get('tier', 'none'),
            "overall_reasons": overall.get('reasons', []),
            "highest_severity": highest.value if highest else 'none',
            "scanner_version": "2.0.0",
            "report_version": "3.2",
            "engine_version": "2.0.0",
            "detection_rules_version": "1.5.0",
            "template_version": "3.2",
            "coverage_total": coverage['total'],
            "coverage_executed": coverage['executed'],
            "coverage_skipped": coverage['skipped'],
            "coverage_failed": coverage['failed'],
            "coverage_not_applicable": coverage['not_applicable'],
            "coverage_percentage": coverage['coverage'],
            "coverage_explanation": coverage.get('explanation', ''),
            "execution_states": coverage.get('states', {}),
            "payload_testing": self.get_payload_testing_status(),
            "labels": {
                "verification": VERIFICATION_LABELS,
                "execution_state": {
                    (k.value if hasattr(k, 'value') else k): v
                    for k, v in EXECUTION_STATE_LABELS.items()
                },
            },
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
            "correlations_found": self.correlation_results.get('correlations_found', 0),
            "correlation_details": self.correlation_results.get('details', []),
            "auth": self._auth_stats(),
        }
        auth_stats = result["auth"]
        result["auth_execution_state"] = auth_stats["state"]
        result["auth_execution_label"] = auth_stats["state_label"]
        return result