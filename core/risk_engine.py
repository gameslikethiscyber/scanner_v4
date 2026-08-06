"""
Risk Engine v3.0 — single owner of the scan-wide weighted risk score.

Moves the v2 RiskCalculator formula here (identical numbers) and adds optional
correlation risk multipliers (v3). Consumes findings only; never assigns severity.

See docs/ENGINE_ARCHITECTURE_V3.md §5.5 and §6.1.
"""

import logging
from typing import Dict, List, Optional, Tuple

from core.finding import Finding, Severity, Status
from core.assessment import RiskResult
from core.assessment_config import RISK as _RCFG

logger = logging.getLogger('SeaScanner.RiskEngine')


class RiskEngine:
    """Computes the weighted risk score 0-100 with a per-finding audit trail."""

    SEVERITY_WEIGHTS = {
        Severity(v): _RCFG["SEVERITY_WEIGHTS"][v]
        for v in _RCFG["SEVERITY_WEIGHTS"]
    }

    # v2 vocabulary ('verified') and v3 vocabulary ('confirmed') both map to 1.0.
    VERIFICATION_MULTIPLIERS = dict(_RCFG["VERIFICATION_MULTIPLIERS"])

    # Warnings are NOT vulnerabilities (SOP Issue #5). Each warning contributes
    # a small bounded "load" (WARNING_UNIT ≈ 0.5 points) that is EXCLUDED from
    # the max_possible denominator, so 4 warnings ≈ 2% and warnings can never
    # dominate the score of a scan with zero confirmed vulnerabilities.
    WARNING_UNIT = _RCFG["WARNING_UNIT"]
    WARNING_LOAD_CAP = _RCFG["WARNING_LOAD_CAP"]
    OCCURRENCE_FLOOR = _RCFG["OCCURRENCE_FLOOR"]
    OCCURRENCE_SCALE = _RCFG["OCCURRENCE_SCALE"]
    MAX_OCCURRENCE_CAP = _RCFG["MAX_OCCURRENCE_CAP"]

    GRADE_BANDS = tuple(_RCFG["GRADE_BANDS"])
    GRADE_F = _RCFG["GRADE_F"]

    CALCULATION_FORMULA = (
        "risk_score = (sum(severity_weight * confidence_factor * "
        "verification_multiplier * (0.8 + 0.2 * occurrences_factor)) "
        "+ bounded warning load) / sum(severity_weight) * 100; "
        "each warning adds at most {0} point(s) of load (no severity denominator)"
    ).format(WARNING_UNIT)

    def calculate(self, findings: List[Finding],
                  correlation_multipliers: Optional[Dict[str, float]] = None) -> RiskResult:
        """Compute the scan-wide risk score.

        ``correlation_multipliers`` maps module name -> multiplier applied to that
        finding's contribution (v3 correlation rules). When omitted, output matches
        v2 RiskCalculator exactly.
        """
        correlation_multipliers = correlation_multipliers or {}
        vuln_findings = [f for f in findings if f.is_vulnerable()]
        warning_findings = [f for f in findings if f.status == Status.WARNING]

        vuln_weighted = 0.0
        vuln_max_possible = 0.0
        warning_load = 0.0
        warning_entries: List[Dict] = []
        breakdown: List[Dict] = []
        explanation: List[str] = []

        for f in vuln_findings:
            sev_weight = self.SEVERITY_WEIGHTS.get(self._severity(f.severity), 1)
            confidence_factor = f.confidence / 100.0
            verification_mult = self.VERIFICATION_MULTIPLIERS.get(f.verification_status, 0.3)
            occurrences_factor = min(f.occurrences, self.MAX_OCCURRENCE_CAP) / float(self.MAX_OCCURRENCE_CAP)

            score = sev_weight * confidence_factor * verification_mult \
                * (self.OCCURRENCE_FLOOR + self.OCCURRENCE_SCALE * occurrences_factor)

            multiplier = correlation_multipliers.get(f.module)
            corr_note = ""
            if multiplier:
                score *= multiplier
                corr_note = f" correlation multiplier x{multiplier}"

            vuln_weighted += score
            vuln_max_possible += sev_weight

            breakdown.append({
                "module": f.module, "severity": f.severity.value,
                "confidence": f.confidence, "verification": f.verification_status,
                "occurrences": f.occurrences, "score": round(score, 2),
                "severity_weight": sev_weight, "confidence_factor": round(confidence_factor, 2),
                "verification_multiplier": verification_mult,
                "occurrences_factor": round(occurrences_factor, 2),
                "correlation_multiplier": multiplier or 1.0,
            })
            explanation.append(
                f"{f.module} contributes {score:.2f}: severity weight {sev_weight} x "
                f"confidence {f.confidence}% (x{confidence_factor:.2f}) x "
                f"verification '{f.verification_status}' (x{verification_mult}) x "
                f"occurrences {f.occurrences} (x{occurrences_factor:.2f}){corr_note}"
            )

        for f in warning_findings:
            # Bounded warning load: warnings are informational, not
            # vulnerabilities. Each adds WARNING_UNIT points (not severity-
            # weighted) and is excluded from max_possible so a scan with only
            # warnings resolves to a small, honest score.
            load = min(self.WARNING_UNIT, self.WARNING_LOAD_CAP)

            warning_load += load
            warning_entries.append({
                "module": f.module, "severity": f.severity.value,
                "confidence": f.confidence, "verification": f.verification_status,
                "occurrences": f.occurrences, "score": round(load, 2),
                "warning": True,
            })
            explanation.append(
                f"{f.module} (warning) adds {load:.2f} point(s) of bounded "
                f"warning load (SOP: ~0.5/warning; not severity-weighted)"
            )

        max_possible = vuln_max_possible
        total_weighted = vuln_weighted + warning_load
        breakdown.extend(warning_entries)

        if max_possible > 0:
            # Clamp so correlation multipliers never push total past the maximum.
            total_weighted = min(total_weighted, max_possible)
            risk_score = round((total_weighted / max_possible) * 100, 1)
        else:
            # No vulnerabilities: the risk score equals the small warning load.
            risk_score = round(min(total_weighted, self.WARNING_LOAD_CAP), 1)

        grade = self.grade_for(risk_score)

        if explanation:
            summary = (
                f"The risk score is {risk_score}%: the weighted contribution of "
                f"{len(vuln_findings)} confirmed vulnerability finding(s) over the "
                f"max possible severity weight, plus a bounded informational "
                f"warning load of {warning_load:.2f} point(s) from "
                f"{len(warning_findings)} warning(s). Warnings are not "
                f"vulnerabilities: they add ~0.5 points each and never move the "
                f"score toward the severity scale."
            )
        else:
            summary = (
                f"The risk score is 0% because no vulnerabilities or warnings were "
                f"reported during the scan."
            )

        return RiskResult(
            risk_score=risk_score,
            security_grade=grade,
            total_weighted=round(total_weighted, 2),
            max_possible=round(max_possible, 2),
            breakdown=breakdown,
            explanation=explanation,
            summary=summary,
            vulnerability_count=len(vuln_findings),
            warning_count=len(warning_findings),
            calculation_formula=self.CALCULATION_FORMULA,
        )

    def grade_for(self, risk_score: float) -> str:
        for upper, grade in self.GRADE_BANDS:
            if risk_score <= upper:
                return grade
        return self.GRADE_F

    @staticmethod
    def _severity(value) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return Severity(value)
        except Exception:
            return Severity.NONE
