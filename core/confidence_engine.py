"""
Confidence Engine v3.0 — single owner of per-finding confidence (0-100).

Consumes an EvidenceScore (Evidence Engine) plus optional correlation / cross
validation boosts and produces an auditable ConfidenceResult. The formula matches
the archived v2_apply_evidence_assessment() exactly so Phase B can prove parity.

See docs/ENGINE_ARCHITECTURE_V3.md §5.2 and §6.2.
"""

import logging
from typing import Any, Dict, List, Optional, Set

from core.assessment import ConfidenceResult, EvidenceScore
from core.assessment_config import CONFIDENCE, CALIBRATED_CONFIDENCE
from core import feature_flags as _ff

logger = logging.getLogger('SeaScanner.ConfidenceEngine')


class ConfidenceEngine:
    """Computes finding confidence from evidence scoring.

    Constants are single-sourced from core.assessment_config (P4.2). The default
    (flag off) path is byte-identical to the frozen v4.9.0 defaults; no behavior
    change. When ``SEA_CALIBRATION`` is enabled (P4.3) the normalized
    ``CALIBRATED_CONFIDENCE`` profile is used instead, reconciling confidence
    caps with verification bands and blending evidence_quality into the base.
    """

    def _profile(self) -> Dict[str, Any]:
        """Pick the active confidence profile based on the calibration flag."""
        if _ff.enabled():
            return CALIBRATED_CONFIDENCE
        return CONFIDENCE

    # Default (frozen v4.2) constants — kept as class attributes so legacy
    # callers/tests that read them still observe the frozen values.
    BASE_ANCHOR = CONFIDENCE["BASE_ANCHOR"]
    MULTIPLE_EVIDENCE_BONUS = CONFIDENCE["MULTIPLE_EVIDENCE_BONUS"]
    VERIFICATION_PASS_SINGLE_BONUS = CONFIDENCE["VERIFICATION_PASS_SINGLE_BONUS"]
    VERIFICATION_PASS_MULTI_BONUS = CONFIDENCE["VERIFICATION_PASS_MULTI_BONUS"]
    CROSS_VALIDATION_BONUS = CONFIDENCE["CROSS_VALIDATION_BONUS"]
    ERROR_PENALTY = CONFIDENCE["ERROR_PENALTY"]
    CORRELATION_BOOST = CONFIDENCE["CORRELATION_BOOST"]
    CROSS_VALIDATED_BOOST = CONFIDENCE["CROSS_VALIDATED_BOOST"]
    MAX_CONFIDENCE_START = CONFIDENCE["MAX_CONFIDENCE_START"]
    CAP_EXPLOITED = CONFIDENCE["CAP_EXPLOITED"]
    CAP_VERIFIED = CONFIDENCE["CAP_VERIFIED"]
    CAP_CONFIRMED = CONFIDENCE["CAP_CONFIRMED"]
    CAP_LIKELY = CONFIDENCE["CAP_LIKELY"]
    CAP_POSSIBLE = CONFIDENCE["CAP_POSSIBLE"]
    CAP_ERROR = CONFIDENCE["CAP_ERROR"]

    _LEVEL_ORDER = tuple(CONFIDENCE["LEVEL_ORDER"])

    def compute(self, evidence_score: EvidenceScore,
                correlation_boost: int = 0,
                cross_validated: bool = False) -> ConfidenceResult:
        """Compute confidence for one finding.

        ``correlation_boost`` is the Confidence Engine's applied boost (0 for none;
        v2 parity uses +5 when the finding was correlation-escalated).
        ``cross_validated`` marks findings confirmed by multiple independent passes.

        When ``SEA_CALIBRATION`` is enabled the normalized profile is used (P4.3):
        caps reconcile with verification bands and ``evidence_quality`` is blended
        into the base (audit C2 — previously unused). Default path is unchanged.
        """
        P = self._profile()
        if evidence_score.evidence_count == 0:
            return ConfidenceResult(
                confidence=0,
                factors={},
                explanation=(
                    "Confidence 0% with no recorded evidence. "
                    "Raise confidence by collecting concrete evidence."
                ),
                verification_passes=0,
                cross_validated=cross_validated,
            )

        # Rebuild v2-style confidence factors from the per-evidence bonus map.
        factors: Dict[str, int] = dict(evidence_score.bonus_factors)
        has_error = evidence_score.has_error
        verification_passes = set(evidence_score.verification_passes)
        has_cross_validation = evidence_score.has_cross_validation

        if evidence_score.total_weight > 0:
            base = evidence_score.weighted_bonus // evidence_score.total_weight + P["BASE_ANCHOR"]
        else:
            base = P["BASE_ANCHOR"]

        # P4.3 (calibrated only): blend evidence_quality into the base so the
        # currently-unused quality signal lifts/drags confidence (audit C2). We
        # take the max of the legacy base and the quality-blended base so the
        # calibrated path never *lowers* confidence vs the frozen default for
        # the same evidence — only enriches it (monotonic, deterministic).
        if _ff.enabled():
            w = P.get("EVIDENCE_QUALITY_WEIGHT", 0.0)
            eq = evidence_score.evidence_quality
            quality_base = P["BASE_ANCHOR"] + int(round((eq - P["BASE_ANCHOR"]) * w)) \
                if eq >= P["BASE_ANCHOR"] else P["BASE_ANCHOR"] - int(
                round((P["BASE_ANCHOR"] - eq) * w))
            base = max(base, quality_base)
            factors["Calibrated: evidence_quality"] = eq

        if evidence_score.evidence_count >= 2 and not has_error:
            base += P["MULTIPLE_EVIDENCE_BONUS"]
            factors["Multiple Evidences"] = P["MULTIPLE_EVIDENCE_BONUS"]

        if len(verification_passes) >= 2:
            base += P["VERIFICATION_PASS_MULTI_BONUS"]
            factors["Multi-pass verification"] = P["VERIFICATION_PASS_MULTI_BONUS"]
        elif len(verification_passes) >= 1:
            base += P["VERIFICATION_PASS_SINGLE_BONUS"]
            factors["Verification pass"] = P["VERIFICATION_PASS_SINGLE_BONUS"]

        if has_cross_validation:
            base += P["CROSS_VALIDATION_BONUS"]
            factors["Cross-validation"] = P["CROSS_VALIDATION_BONUS"]

        # Max-confidence cap chain (order-preserving for exact v2 parity).
        max_confidence = P["MAX_CONFIDENCE_START"]
        has_exploited = False
        has_verified = False
        for level in evidence_score.level_sequence:
            if level == 'exploited':
                max_confidence = P["CAP_EXPLOITED"]
                has_exploited = True
            elif level == 'verified':
                if not has_exploited:
                    max_confidence = P["CAP_VERIFIED"]
                has_verified = True
            elif level == 'confirmed':
                if not has_exploited and not has_verified:
                    max_confidence = P["CAP_CONFIRMED"]
            elif level == 'likely':
                if not has_exploited and not has_verified and max_confidence > P["CAP_CONFIRMED"]:
                    max_confidence = P["CAP_LIKELY"]
            elif level == 'possible':
                if max_confidence > P["CAP_LIKELY"]:
                    max_confidence = P["CAP_POSSIBLE"]

        if has_error:
            max_confidence = min(max_confidence, P["CAP_ERROR"])
            factors["Error detected"] = -P["ERROR_PENALTY"]

        if correlation_boost > 0:
            max_confidence = min(100, max_confidence + correlation_boost)
            factors["Correlation boost"] = correlation_boost

        if cross_validated:
            max_confidence = min(100, max_confidence + P["CROSS_VALIDATED_BOOST"])
            factors["Cross-validated"] = P["CROSS_VALIDATED_BOOST"]

        confidence = max(0, min(max_confidence, base))

        return ConfidenceResult(
            confidence=confidence,
            factors=factors,
            explanation=self._build_explanation(confidence, evidence_score, factors),
            verification_passes=len(verification_passes),
            cross_validated=cross_validated,
        )

    def _build_explanation(self, confidence: int, evidence_score: EvidenceScore,
                           factors: Dict[str, int]) -> str:
        strongest = evidence_score.strongest_level
        strongest_label = strongest.replace('_', ' ').title()
        n = evidence_score.evidence_count
        verified_count = sum(
            1 for level in evidence_score.level_sequence
            if level in ('verified', 'exploited')
        )
        parts = [
            f"Confidence {confidence}% from {n} evidence item(s)",
            f"strongest evidence level {strongest_label}",
        ]
        if verified_count:
            parts.append(f"{verified_count} item(s) fully verified")
        if evidence_score.has_error:
            parts.append("error evidence detected (hard cap 40%)")
        return "; ".join(parts) + "."
