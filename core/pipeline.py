"""
Engine Pipeline v3.0 — the shared per-finding scoring entry point.

Order of engines: Evidence → Confidence → Verification → Severity. Results are
written back onto the raw Finding exactly where the archived v2 decision logic
wrote them, so the pipeline can be proven equivalent to the archived
``tests.v2_reference.v2_decide()`` on identical input (Phase B0). It is the body
of ``BaseScanner.run()`` (Phase A8).

``run_assessment_pipeline`` also runs the scan-wide engines (Risk → Coverage →
Assessment) and returns the single immutable ``Assessment``.

See docs/ENGINE_ARCHITECTURE_V3.md §5 and §7.
"""

import logging
from typing import Any, Dict, List, Optional

from core.assessment import Assessment, CoverageReport, RiskResult, SeverityResult
from core.confidence_engine import ConfidenceEngine
from core.coverage_engine import CoverageEngine
from core.decision_engine import DecisionEngine
from core.evidence import EvidenceLevel
from core.evidence_engine import EvidenceEngine
from core.finding import (
    Finding, Status, Severity, Exploitability, POSITIVE_OBSERVATION_TERMS,
)
from core.risk_engine import RiskEngine
from core.severity_engine import SeverityEngine
from core.verification_engine import VerificationEngine

logger = logging.getLogger('SeaScanner.Pipeline')


def run_engine_pipeline(finding: Finding, *,
                        correlation_escalation: Optional[str] = None,
                        correlation_boost: int = 0,
                        cross_validated: bool = False) -> Finding:
    """Apply Evidence → Confidence → Verification → Severity to one finding.

    The module map from the standards provider is the single source of truth
    for severity (scanner presets are never honored — A8.9 freeze).
    """
    _determine_status(finding)

    evidence_score = EvidenceEngine().score(finding.evidence)
    finding.evidence_quality = evidence_score.evidence_quality

    confidence_result = ConfidenceEngine().compute(
        evidence_score,
        correlation_boost=correlation_boost if finding.correlation_escalated else 0,
        cross_validated=cross_validated or finding.cross_validated,
    )
    finding.confidence = confidence_result.confidence
    finding.confidence_factors = dict(confidence_result.factors)
    finding.confidence_explanation = confidence_result.explanation
    finding.verification_passes = confidence_result.verification_passes
    finding.cross_validated = confidence_result.cross_validated

    classification = VerificationEngine.classify(
        confidence_result.confidence,
        evidence_levels=_evidence_levels(finding.evidence),
        has_error=evidence_score.has_error,
    )
    # Report vocabulary (v2 parity): internal 'confirmed' is reported as
    # 'verified'; the raw v3 band is kept separately for v3 consumers.
    finding.verification_status = _VERIFICATION_REPORT_MAP.get(
        classification.status, classification.status
    )
    finding.verification_class = classification.status

    severity_result = SeverityEngine().assess(
        finding,
        verification_status=None,
        correlation_escalation=correlation_escalation,
    )
    _apply_severity(finding, severity_result)

    _ensure_reason_recommendation(finding)
    # SOP #6: positive observations must never be reported as warnings (v2 parity).
    _reclassify_positive_warnings(finding)
    # Single owner: the Coverage Engine classifies execution state (the archived
    # v2_compute_execution_state diverged on UNKNOWN findings).
    state, reason = CoverageEngine.classify_execution_state(finding)
    finding.execution_state = state
    finding.state_reason = reason
    return finding


def apply_correlation_payloads(findings: List[Finding],
                               payloads: Dict[int, Dict[str, Any]]) -> None:
    """Apply non-mutating CorrelationEngine payloads with exact v2 semantics.

    Mirrors v2 ``CorrelationEngine._apply_correlation``: flat confidence boost,
    upward-only severity escalation, and correlation flags. Risk multipliers are
    NOT folded into severity/confidence here — consumers pass them to the Risk
    Engine explicitly (v3 enhancement, off by default for parity).
    """
    order = {'none': 0, 'info': 1, 'low': 2, 'medium': 3, 'high': 4, 'critical': 5}
    for f in findings:
        payload = payloads.get(id(f))
        if not payload:
            continue
        boost = payload.get('confidence_boost', 0)
        if boost:
            f.confidence = min(100, f.confidence + boost)
            f.confidence_factors = dict(f.confidence_factors or {})
            f.confidence_factors['correlation'] = f.confidence_factors.get('correlation', 0) + boost
        escalation = payload.get('severity_escalation')
        if escalation:
            new_sev = Severity(escalation)
            if order.get(new_sev.value, 0) > order.get(f.severity.value, 0):
                f.severity = new_sev
                f.correlation_escalated = True


def run_assessment_pipeline(scan_result: Any, *,
                            correlation_multipliers: Optional[Dict[str, float]] = None,
                            metadata: Optional[Dict[str, Any]] = None) -> Assessment:
    """Run per-finding engines + correlation + scan-wide engines → Assessment.

    This is the single assessment lifecycle (Phase A9): every production
    orchestrator calls it exactly once per scan and the returned immutable
    ``Assessment`` is stored on ``scan_result.assessment`` so all consumers
    (reporters, GUI, CLI, backend) read the same object. The call is
    idempotent: a second call returns the already-built Assessment without
    re-running the engines (correlation boosts must never be applied twice).

    When ``correlation_multipliers`` is None the Risk Engine output matches v2
    RiskCalculator exactly (correlation affects risk only through the confidence
    boosts / severity escalations applied here, as in v2).
    """
    existing = getattr(scan_result, 'assessment', None)
    if existing is not None:
        return existing

    for finding in scan_result.findings:
        run_engine_pipeline(finding)

    _apply_correlation_pipeline(scan_result)

    risk = RiskEngine().calculate(
        scan_result.findings, correlation_multipliers=correlation_multipliers
    )
    coverage = CoverageEngine().report(scan_result.findings, scan_result.total_modules)

    from core.assessment_engine import AssessmentEngine
    assessment = AssessmentEngine().build(
        scan_result,
        coverage=coverage,
        risk=risk,
        correlation_multipliers=correlation_multipliers,
        metadata=metadata,
    )
    if hasattr(scan_result, 'assessment'):
        scan_result.assessment = assessment
    return assessment


def _apply_correlation_pipeline(scan_result: Any) -> None:
    """Compute correlation payloads and apply v2-exact boosts/escalations."""
    try:
        from core.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        _, payloads, module_multipliers = engine.correlation_payloads(scan_result.findings)
        apply_correlation_payloads(scan_result.findings, payloads)
        scan_result.correlation_results = engine.get_correlation_summary()
        for f in scan_result.findings:
            multiplier = module_multipliers.get(f.module)
            if multiplier:
                f.correlation_findings = list(
                    set(getattr(f, 'correlation_findings', []) or []) | {f.module}
                )
    except Exception as exc:  # never break a scan because correlation failed
        logger.warning("Correlation pipeline failed: %s", exc)
        scan_result.correlation_results = {'correlations_found': 0, 'details': []}


# ===== helpers =====

# Internal v3 verification band → v2 report vocabulary.
_VERIFICATION_REPORT_MAP = {'confirmed': 'verified'}


def _reclassify_positive_warnings(finding: Finding) -> None:
    """SOP #6: positive observations must never be reported as warnings (v2 parity)."""
    if finding.status is not Status.WARNING:
        return
    first_ev = getattr(finding.evidence[0], 'description', '') if finding.evidence else ''
    text = " ".join([
        finding.reason or '',
        finding.description or '',
        first_ev,
    ]).lower()
    if any(term in text for term in POSITIVE_OBSERVATION_TERMS):
        finding.status = Status.PASS
        finding.severity = Severity.NONE
        if not finding.reason:
            finding.reason = "Positive security observation confirmed."
        if not finding.recommendation or finding.recommendation.startswith('Review'):
            finding.recommendation = DecisionEngine.PASS_RECOMMENDATION


def _determine_status(finding: Finding) -> None:
    """Evidence-level → status mapping for provisional (UNKNOWN) findings (v2 parity)."""
    if finding.status not in (Status.UNKNOWN,):
        return
    if not finding.evidence:
        finding.status = Status.UNKNOWN
        return

    def _level(e):
        lvl = getattr(e, 'level', None)
        if lvl is None:
            return None
        if isinstance(lvl, EvidenceLevel):
            return lvl
        try:
            return EvidenceLevel(lvl)
        except Exception:
            return None

    levels = [_level(e) for e in finding.evidence]

    has_error_evidence = any(
        lvl is not None and lvl == EvidenceLevel.UNKNOWN
        and 'error' in getattr(e, 'description', '').lower()
        for e, lvl in zip(finding.evidence, levels)
    )
    if has_error_evidence:
        finding.status = Status.UNKNOWN
        return

    confirmed_levels = {EvidenceLevel.EXPLOITED, EvidenceLevel.CONFIRMED}
    confirmed = any(lvl in confirmed_levels for lvl in levels)
    if confirmed:
        finding.status = Status.FAIL
    elif any(lvl == EvidenceLevel.LIKELY for lvl in levels):
        finding.status = Status.WARNING
    elif any(lvl == EvidenceLevel.POSSIBLE for lvl in levels):
        finding.status = Status.UNKNOWN
    else:
        finding.status = Status.PASS


def _evidence_levels(evidence: List[Any]) -> List[str]:
    levels = []
    for ev in evidence:
        lvl = getattr(ev, 'level', None)
        raw = getattr(lvl, 'value', None) or lvl or 'unknown'
        levels.append(str(raw).lower())
    return levels


def _apply_severity(finding: Finding, result: SeverityResult) -> None:
    finding.severity = _severity_enum(result.severity)
    finding.exploitability = _exploitability_enum(result.exploitability)
    finding.impact = dict(result.impact)
    finding.cvss_score = result.cvss_score
    finding.cvss_vector = result.cvss_vector
    finding.cvss_explanation = result.cvss_explanation
    finding.cwe_id = result.cwe_id or ''
    finding.owasp_category = result.owasp_category or ''
    finding.capec_id = result.capec_id or ''
    finding.mitre_id = result.mitre_id or ''
    finding.asvs_reference = result.asvs_reference or ''


def _ensure_reason_recommendation(finding: Finding) -> None:
    """Fill reason/recommendation from standards metadata when empty (v2 parity)."""
    de = DecisionEngine
    if finding.status == Status.PASS and not finding.reason:
        finding.reason = de.PASS_REASON
    if finding.status == Status.PASS and not finding.recommendation:
        finding.recommendation = de.PASS_RECOMMENDATION

    if not finding.reason:
        module = finding.module
        evidence_desc = ''
        if finding.evidence:
            desc = getattr(finding.evidence[0], 'description', '') or ''
            if desc:
                evidence_desc = desc.lower()
        if finding.status == Status.FAIL:
            finding.reason = (
                f'{de.FAIL_REASON_PREFIX}{evidence_desc}'
                if evidence_desc else f'{module} vulnerability detected'
            )
        elif finding.status == Status.WARNING:
            finding.reason = (
                f'{de.WARNING_REASON_PREFIX}{evidence_desc}'
                if evidence_desc else f'{module} requires review'
            )

    if not finding.recommendation:
        module = finding.module
        if module in de.RECOMMENDATIONS:
            finding.recommendation = de.RECOMMENDATIONS[module]
        else:
            finding.recommendation = (
                f'Review {module} configuration and apply security best practices.'
            )


def _severity_enum(value: str) -> Severity:
    try:
        return Severity(value)
    except Exception:
        return Severity.NONE


def _exploitability_enum(value: str) -> Exploitability:
    try:
        return Exploitability(value)
    except Exception:
        return Exploitability.UNKNOWN
