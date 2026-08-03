"""
Coverage Engine v3.0 — single owner of scan completeness and assessment confidence impact.

Classifies every finding into an ExecutionState, computes executed/skipped/failed/na
counts, coverage percentage, coverage quality and the delta applied to assessment
confidence. The v2 counting quirk (status-UNKNOWN findings counted as "skipped" in
execution states but not by get_skipped_findings()) is fixed here: execution-incomplete
findings classify as NOT_APPLICABLE, so executed+skipped+not_applicable always equals
total and the strict validation rule holds.

See docs/ENGINE_ARCHITECTURE_V3.md §5.6 and §6.4.
"""

import logging
from typing import Dict, List, Tuple

from core.finding import Finding, Status, ExecutionState, EXECUTION_STATE_LABELS
from core.assessment import CoverageReport
from core.assessment_config import COVERAGE as _CCFG

logger = logging.getLogger('SeaScanner.CoverageEngine')


class CoverageEngine:
    """Computes scan coverage and its impact on assessment confidence."""

    # Coverage quality penalties (per fraction of total, see docs §6.4).
    FAILED_PENALTY = _CCFG["FAILED_PENALTY"]
    SKIPPED_PENALTY = _CCFG["SKIPPED_PENALTY"]
    NOT_APPLICABLE_PENALTY = _CCFG["NOT_APPLICABLE_PENALTY"]

    # Coverage quality -> assessment confidence delta (docs §6.4).
    CONFIDENCE_IMPACT_SCALE = _CCFG["CONFIDENCE_IMPACT_SCALE"]

    @classmethod
    def classify_execution_state(cls, finding: Finding) -> Tuple[ExecutionState, str]:
        """Classify one finding into an ExecutionState (single owner; archived
        v2_compute_execution_state diverged on UNKNOWN findings)."""
        status = finding.status
        if status in (Status.FAIL, Status.VULNERABLE, Status.ERROR):
            return ExecutionState.FAILED, "Vulnerability confirmed or scan error detected"
        if status is Status.WARNING:
            return ExecutionState.WARNING, finding.reason or "Potential issue requires review"
        if status is Status.INFO:
            return ExecutionState.INFO, finding.reason or "Informational observation"
        if finding.is_skipped():
            return ExecutionState.SKIPPED, finding.skip_reason or "Module skipped"
        if status in (Status.PASS, Status.SAFE):
            if finding.tests_performed == 0 and finding.tests_run == 0:
                return ExecutionState.NOT_APPLICABLE, (
                    finding.reason
                    or "No tests were executed; module not applicable to this target"
                )
            return ExecutionState.PASSED, finding.reason or "No vulnerabilities detected"
        # UNKNOWN / other statuses without skip: execution incomplete.
        return ExecutionState.NOT_APPLICABLE, (
            finding.reason or "Execution incomplete; no conclusion could be reached"
        )

    def report(self, findings: List[Finding], total_modules: int = 0) -> CoverageReport:
        counts: Dict[ExecutionState, int] = {state: 0 for state in ExecutionState}
        details = []

        for finding in findings:
            state, reason = self.classify_execution_state(finding)
            counts[state] += 1
            details.append({
                'module': finding.module,
                'state': state.value,
                'label': EXECUTION_STATE_LABELS.get(state, state.value),
                'reason': reason or finding.reason or '',
                'tests': finding.tests_performed,
                'duration': finding.duration,
            })

        passed = counts[ExecutionState.PASSED]
        failed = counts[ExecutionState.FAILED]
        warning = counts[ExecutionState.WARNING]
        info = counts[ExecutionState.INFO]
        executed = passed + failed + warning + info
        skipped = counts[ExecutionState.SKIPPED]
        not_applicable = counts[ExecutionState.NOT_APPLICABLE]

        total = total_modules if total_modules > 0 else len(findings)
        coverage_percent = int((executed / total) * 100) if total > 0 else 0

        coverage_quality = 100
        if total > 0:
            coverage_quality = (
                100 * (executed / total)
                - self.FAILED_PENALTY * (failed / total)
                - self.SKIPPED_PENALTY * (skipped / total)
                - self.NOT_APPLICABLE_PENALTY * (not_applicable / total)
            )
        coverage_quality = max(0, min(100, round(coverage_quality)))
        assessment_confidence_impact = 0
        if total > 0:
            assessment_confidence_impact = -round((100 - coverage_quality) / self.CONFIDENCE_IMPACT_SCALE)

        # Per-reason module groupings for skipped / not_applicable.
        skip_reasons: Dict[str, List[str]] = {}
        for d in details:
            if d['state'] in ('skipped', 'not_applicable') and d['reason']:
                key = d['reason'][:60]
                if key not in skip_reasons:
                    skip_reasons[key] = []
                skip_reasons[key].append(d['module'])

        explanation_parts = []
        if skipped:
            skipped_names = [d['module'] for d in details if d['state'] == 'skipped']
            explanation_parts.append(
                f"{skipped} module(s) skipped ({', '.join(skipped_names[:5])})"
            )
        if not_applicable:
            na_names = [d['module'] for d in details if d['state'] == 'not_applicable']
            explanation_parts.append(
                f"{not_applicable} module(s) not applicable ({', '.join(na_names[:5])})"
            )
        if failed:
            explanation_parts.append(f"{failed} module(s) failed")

        if explanation_parts:
            explanation = "Coverage reduced because " + "; ".join(explanation_parts) + "."
        else:
            explanation = "All modules executed successfully; coverage reflects full scan."

        execution_states = {
            'passed': passed,
            'failed': failed,
            'skipped': skipped,
            'not_applicable': not_applicable,
            'warning': warning,
            'info': info,
            'auth_required': counts[ExecutionState.AUTH_REQUIRED],
            'authenticated': counts[ExecutionState.AUTHENTICATED],
            'public_only': counts[ExecutionState.PUBLIC_ONLY],
            'session_expired': counts[ExecutionState.SESSION_EXPIRED],
            'login_failed': counts[ExecutionState.LOGIN_FAILED],
            'token_invalid': counts[ExecutionState.TOKEN_INVALID],
            'executed': executed,
            'total': total,
            'details': details,
            'explanation': explanation,
        }

        return CoverageReport(
            total=total,
            executed=executed,
            passed=passed,
            failed=failed,
            warning=warning,
            info=info,
            skipped=skipped,
            not_applicable=not_applicable,
            coverage_percent=coverage_percent,
            coverage_quality=coverage_quality,
            execution_states=execution_states,
            skip_reasons=skip_reasons,
            explanation=explanation,
            assessment_confidence_impact=assessment_confidence_impact,
        )
