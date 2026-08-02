"""
v2 assessment reference — archived for regression testing and historical comparison.

Phase A8.9 (Migration Cleanup & Architecture Freeze) removed every legacy v2
decision/assessment routine from production. Those routines are preserved here,
verbatim, so the validation harnesses can still reproduce the v2 engine output:

  * ``v2_apply_evidence_assessment`` — the v2 ``Finding.add_evidence()`` auto
    assessment side effect (confidence, verification, matched rules).
  * ``V2DecisionEngine`` / ``v2_decide`` — the v2 ``DecisionEngine.decide()``
    pipeline and its helpers.
  * ``v2_compute_execution_state``   — the legacy execution-state classifier.

IMPORTANT: this module is used ONLY by the validation harnesses
(tests/engine_paths.py, tests/regression_runner.py, tests/live_scan_runner.py,
test_validation.py). Production code must never import it. The production system
contains only the v3 engine pipeline.
"""

from typing import Dict, List

from core.decision_engine import DecisionEngine
from core.evidence import EvidenceLevel
from core.finding import (
    Finding,
    POSITIVE_OBSERVATION_TERMS,
    Severity,
    Status,
    Exploitability,
    ExecutionState,
)

__all__ = [
    "v2_apply_evidence_assessment",
    "V2DecisionEngine",
    "v2_decide",
    "v2_compute_execution_state",
]

# Archived copy of the v2 evidence-level label map (removed from core/finding.py).
EVIDENCE_LEVEL_LABELS = {
    'verified': 'Verified',
    'exploited': 'Exploited',
    'confirmed': 'Confirmed',
    'likely': 'Likely',
    'possible': 'Possible',
    'unknown': 'Unknown',
    'not_tested': 'Not Tested',
}


# =====================================================================
# v2 evidence auto-assessment (the archived add_evidence() side effect)
# =====================================================================

def v2_highest_evidence_level(finding: Finding) -> str:
    best = "unknown"
    order = ("unknown", "not_tested", "possible", "likely", "confirmed", "verified", "exploited")
    for ev in finding.evidence:
        lvl = getattr(ev, 'level', None)
        raw = getattr(lvl, 'value', None) or lvl or "unknown"
        raw = str(raw).lower()
        if raw in order and order.index(raw) > order.index(best):
            best = raw
    return best


def v2_build_confidence_explanation(finding: Finding) -> str:
    if not finding.evidence:
        return (
            f"Confidence {finding.confidence}% with no recorded evidence. "
            "Raise confidence by collecting concrete evidence."
        )
    highest = v2_highest_evidence_level(finding)
    highest_label = EVIDENCE_LEVEL_LABELS.get(highest, highest)
    verified = sum(1 for ev in finding.evidence
                   if getattr(getattr(ev, 'level', None), 'value', '') in ('verified', 'exploited'))
    return (
        f"Confidence {finding.confidence}% from {len(finding.evidence)} evidence item(s); "
        f"strongest evidence level {highest_label}; "
        f"{verified} item(s) fully verified; verification status {finding.verification_label}."
    )


def v2_update_verification_status(finding: Finding) -> None:
    levels = [getattr(ev, 'level', None) for ev in finding.evidence]
    if EvidenceLevel.EXPLOITED in levels:
        finding.verification_status = "verified"
    elif EvidenceLevel.VERIFIED in levels:
        finding.verification_status = "verified"
    elif EvidenceLevel.CONFIRMED in levels:
        finding.verification_status = "likely"
    elif EvidenceLevel.LIKELY in levels:
        finding.verification_status = "possible"
    elif EvidenceLevel.POSSIBLE in levels:
        finding.verification_status = "manual_review"
    else:
        finding.verification_status = "unverified"
    finding.confidence_explanation = v2_build_confidence_explanation(finding)


def v2_collect_matched_rules(finding: Finding) -> List[str]:
    rules = []
    for ev in finding.evidence:
        desc = getattr(ev, 'description', '') or ''
        payload = getattr(ev, 'payload', None)
        level = getattr(getattr(ev, 'level', None), 'value', None)
        if desc and (payload is not None or level in ('confirmed', 'verified', 'exploited')):
            if desc not in rules:
                rules.append(desc[:120])
    finding.matched_rules = rules[:10]
    return finding.matched_rules


def v2_apply_evidence_assessment(finding: Finding) -> None:
    """Replicate the v2 add_evidence() side effect for the evidence a finding holds."""
    if not finding.evidence:
        finding.confidence = 0
        return

    factors: Dict[str, int] = {}
    has_error = False

    total_weight = 0
    weighted_bonus = 0

    verification_passes = set()
    has_cross_validation = False

    for ev in finding.evidence:
        bonus = getattr(ev, 'confidence_bonus', 0)
        weight = getattr(ev, 'weight', 1)
        desc = getattr(ev, 'description', '')[:30]
        ev_type = getattr(ev, 'type', None)

        level = getattr(ev, 'level', None)
        if level is EvidenceLevel.UNKNOWN and 'error' in getattr(ev, 'description', '').lower():
            has_error = True
            bonus = min(bonus, -20)

        vpass = getattr(ev, 'verification_pass', 0)
        if vpass > 0:
            verification_passes.add(vpass)

        if ev_type and ev_type.value == 'cross_validation':
            has_cross_validation = True

        if bonus > 0:
            weighted_bonus += bonus * weight
            total_weight += weight
            if bonus != 0:
                factors[f"Evidence: {desc}"] = bonus

    if total_weight > 0:
        base = weighted_bonus // total_weight + 50
    else:
        base = 50

    if len(finding.evidence) >= 2 and not has_error:
        base += 5
        factors["Multiple Evidences"] = 5

    if len(verification_passes) >= 2:
        base += 10
        factors["Multi-pass verification"] = 10
    elif len(verification_passes) >= 1:
        base += 5
        factors["Verification pass"] = 5

    if has_cross_validation:
        base += 10
        factors["Cross-validation"] = 10

    max_confidence = 95
    has_exploited = False
    has_verified = False
    for ev in finding.evidence:
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

    if finding.correlation_escalated:
        max_confidence = min(100, max_confidence + 5)
        factors["Correlation boost"] = 5

    if finding.cross_validated:
        max_confidence = min(100, max_confidence + 5)
        factors["Cross-validated"] = 5

    finding.confidence = max(0, min(max_confidence, base))
    finding.confidence_factors = factors
    finding.verification_passes = len(verification_passes)

    v2_collect_matched_rules(finding)
    v2_update_verification_status(finding)


# =====================================================================
# v2 execution-state classifier (archived Finding.compute_execution_state)
# =====================================================================

def v2_compute_execution_state(finding: Finding) -> ExecutionState:
    if finding.status in (Status.FAIL, Status.VULNERABLE, Status.ERROR):
        finding.execution_state = ExecutionState.FAILED
        finding.state_reason = "Vulnerability confirmed or scan error detected"
    elif finding.status is Status.WARNING:
        finding.execution_state = ExecutionState.WARNING
        finding.state_reason = finding.reason or "Potential issue requires review"
    elif finding.status is Status.INFO:
        finding.execution_state = ExecutionState.INFO
        finding.state_reason = finding.reason or "Informational observation"
    elif finding.is_skipped():
        finding.execution_state = ExecutionState.SKIPPED
        finding.state_reason = finding.skip_reason or "Module skipped"
    elif finding.status in (Status.PASS, Status.SAFE):
        if finding.tests_performed == 0 and finding.tests_run == 0:
            finding.execution_state = ExecutionState.NOT_APPLICABLE
            finding.state_reason = (
                finding.reason
                or "No tests were executed; module not applicable to this target"
            )
        else:
            finding.execution_state = ExecutionState.PASSED
            finding.state_reason = finding.reason or "No vulnerabilities detected"
    else:
        finding.execution_state = ExecutionState.SKIPPED
        finding.state_reason = (
            finding.reason or "Execution incomplete; no conclusion could be reached"
        )
    return finding.execution_state


# =====================================================================
# Archived v2 decide() pipeline
# =====================================================================

class V2DecisionEngine(DecisionEngine):
    """Archived v2 assessment pipeline (subclasses the metadata provider)."""

    def _ensure_reason_recommendation(self, finding: Finding) -> Finding:
        if finding.status == Status.PASS and not finding.reason:
            finding.reason = self.PASS_REASON
        if finding.status == Status.PASS and not finding.recommendation:
            finding.recommendation = self.PASS_RECOMMENDATION

        if not finding.reason:
            module = finding.module
            if finding.status == Status.FAIL:
                evidence_desc = ''
                if finding.evidence:
                    ev = finding.evidence[0]
                    desc = getattr(ev, 'description', '') or ''
                    if desc:
                        evidence_desc = desc.lower()
                finding.reason = (f'{self.FAIL_REASON_PREFIX}{evidence_desc}'
                                  if evidence_desc else f'{module} vulnerability detected')
            elif finding.status == Status.WARNING:
                evidence_desc = ''
                if finding.evidence:
                    ev = finding.evidence[0]
                    desc = getattr(ev, 'description', '') or ''
                    if desc:
                        evidence_desc = desc.lower()
                finding.reason = (f'{self.WARNING_REASON_PREFIX}{evidence_desc}'
                                  if evidence_desc else f'{module} requires review')

        if not finding.recommendation:
            module = finding.module
            if module in self.RECOMMENDATIONS:
                finding.recommendation = self.RECOMMENDATIONS[module]
            else:
                finding.recommendation = (
                    f'Review {module} configuration and apply security best practices.'
                )
        return finding

    def _reclassify_positive_warnings(self, finding: Finding) -> Finding:
        """SOP #6: positive observations must never be reported as warnings."""
        if finding.status is not Status.WARNING:
            return finding
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
                finding.recommendation = self.PASS_RECOMMENDATION
        return finding

    def _populate_replay_data(self, finding: Finding) -> Finding:
        for ev in finding.evidence:
            raw = getattr(ev, 'raw_data', None) or {}
            if not isinstance(raw, dict):
                continue
            req = raw.get('request', {})
            resp = raw.get('response', {})
            if req or resp:
                finding.replay_data = {'request': req, 'response': resp}
                break
        return finding

    def _determine_status(self, finding: Finding) -> Finding:
        if finding.status not in (Status.UNKNOWN,):
            return finding

        if not finding.evidence:
            finding.status = Status.UNKNOWN
            return finding

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
            return finding

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
        return finding

    def _determine_severity(self, finding: Finding) -> Finding:
        if finding.status == Status.PASS:
            finding.severity = Severity.NONE
            return finding
        if finding.severity != Severity.NONE:
            return finding
        if finding.status in (Status.FAIL, Status.WARNING):
            mapped = self.SEVERITY_BY_MODULE.get(finding.module)
            if mapped is not None:
                finding.severity = mapped
            else:
                finding.severity = Severity.MEDIUM
        else:
            finding.severity = Severity.INFO
        return finding

    def _determine_exploitability(self, finding: Finding) -> Finding:
        if finding.severity == Severity.CRITICAL:
            finding.exploitability = Exploitability.EASY
        elif finding.severity == Severity.HIGH:
            finding.exploitability = Exploitability.MEDIUM
        elif finding.severity == Severity.MEDIUM:
            finding.exploitability = Exploitability.HARD
        elif finding.severity == Severity.LOW:
            finding.exploitability = Exploitability.THEORETICAL
        else:
            finding.exploitability = Exploitability.UNKNOWN
        return finding

    def _assign_standards(self, finding: Finding) -> Finding:
        module = finding.module
        entry = self.STANDARDS.get(module)
        if entry:
            finding.cwe_id = entry['cwe']
            finding.owasp_category = entry['owasp']
            finding.capec_id = entry['capec']
            finding.mitre_id = entry['mitre']
            finding.asvs_reference = entry['asvs']
        return finding

    def _assign_impact(self, finding: Finding) -> Finding:
        module = finding.module
        entry = self.STANDARDS.get(module)
        if entry:
            impact = entry['impact']
            multiplier = (
                1.0 if finding.severity == Severity.CRITICAL else
                0.8 if finding.severity == Severity.HIGH else
                0.6 if finding.severity == Severity.MEDIUM else
                0.4 if finding.severity == Severity.LOW else 0.2
            )
            finding.impact = {
                'confidentiality': max(1, int(impact['confidentiality'] * multiplier)),
                'integrity': max(1, int(impact['integrity'] * multiplier)),
                'availability': max(1, int(impact['availability'] * multiplier)),
            }
        return finding

    def _calculate_cvss(self, finding: Finding) -> Finding:
        severity_score = {
            Severity.NONE: 0, Severity.INFO: 1.0, Severity.LOW: 3.0,
            Severity.MEDIUM: 5.0, Severity.HIGH: 7.0, Severity.CRITICAL: 9.0,
        }
        base = severity_score.get(finding.severity, 0)
        confidence_boost = (finding.confidence / 100) * 0.5
        finding.cvss_score = round(min(10, base + confidence_boost), 1)

        av, ac, pr, ui, s = 'N', 'L', 'N', 'N', 'U'
        c, i_val, a = 'N', 'N', 'N'

        imp = finding.impact
        if imp.get('confidentiality', 0) >= 4: c = 'H'
        elif imp.get('confidentiality', 0) >= 2: c = 'L'
        if imp.get('integrity', 0) >= 4: i_val = 'H'
        elif imp.get('integrity', 0) >= 2: i_val = 'L'
        if imp.get('availability', 0) >= 4: a = 'H'
        elif imp.get('availability', 0) >= 2: a = 'L'

        if finding.severity == Severity.CRITICAL:
            av, ac, pr, ui = 'N', 'L', 'N', 'N'
        elif finding.severity == Severity.HIGH:
            av, ac, pr, ui = 'N', 'L', 'L', 'N'
        elif finding.severity == Severity.MEDIUM:
            av, ac, pr, ui = 'N', 'L', 'L', 'R'
        elif finding.severity == Severity.LOW:
            av, ac, pr, ui = 'A', 'H', 'H', 'R'

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i_val}/A:{a}"
        finding.cvss_vector = vector

        parts = vector.replace('CVSS:3.1/', '').split('/')
        explanations = []
        for p in parts:
            desc = self.CVSS_DESCRIPTIONS.get(p.strip())
            if desc:
                explanations.append(desc)

        total_impact = imp.get('confidentiality', 0) + imp.get('integrity', 0) + imp.get('availability', 0)
        finding.cvss_explanation = (
            f"Score {finding.cvss_score} out of 10. "
            f"Computed from severity={finding.severity.value} (base {base}) "
            f"adjusted by confidence {finding.confidence}% (boost +{confidence_boost:.1f}). "
            f"Impact profile: CIA={total_impact}/15. "
            + ' | '.join(explanations)
        )
        return finding

    def _generate_verify_commands(self, finding: Finding) -> Finding:
        target = finding.target
        method = 'GET'
        payload = ''
        for ev in finding.evidence:
            if getattr(ev, 'payload', None):
                payload = ev.payload
            if getattr(ev, 'method', None):
                method = ev.method

        cmds = []
        if target:
            quoted_url = target.replace('"', '\\"')
            cmds.append(f'curl -X {method} -k -v "{quoted_url}"')
            if payload:
                cmds.append(f'curl -X {method} -k -v -H "Host: {payload}" "{quoted_url}"')
            cmds.append(f'# Burp Suite: Send request to Repeater, replace Host header, observe response')
            cmds.append(f'# Browser: Open DevTools (F12) > Network tab, reload page, inspect request/response')
            cmds.append(f'# OWASP ZAP: Right-click request > Open in Browser > Manual Explore')
        finding.verify_commands = cmds
        return finding

    def decide(self, finding: Finding) -> Finding:
        v2_apply_evidence_assessment(finding)
        if not finding.evidence and finding.status is Status.UNKNOWN:
            finding.status = Status.UNKNOWN
            finding.severity = Severity.NONE
            finding.confidence = 0
            self._ensure_reason_recommendation(finding)
            v2_compute_execution_state(finding)
            return finding

        finding = self._determine_status(finding)
        finding = self._determine_severity(finding)
        finding = self._determine_exploitability(finding)
        finding = self._assign_standards(finding)
        finding = self._assign_impact(finding)
        finding = self._calculate_cvss(finding)
        finding = self._generate_verify_commands(finding)
        finding = self._populate_replay_data(finding)
        finding = self._ensure_reason_recommendation(finding)
        finding = self._reclassify_positive_warnings(finding)
        v2_compute_execution_state(finding)
        return finding


def v2_decide(finding: Finding) -> Finding:
    """Convenience wrapper: run the archived v2 decide() on one finding."""
    return V2DecisionEngine().decide(finding)
