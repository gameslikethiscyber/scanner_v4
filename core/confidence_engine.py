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

logger = logging.getLogger('SeaScanner.ConfidenceEngine')


class ConfidenceEngine:
    """Computes finding confidence from evidence scoring."""

    # Base anchor when no weighted evidence bonus exists.
    BASE_ANCHOR = 50

    # Additive adjustments.
    MULTIPLE_EVIDENCE_BONUS = 5
    VERIFICATION_PASS_SINGLE_BONUS = 5
    VERIFICATION_PASS_MULTI_BONUS = 10
    CROSS_VALIDATION_BONUS = 10
    ERROR_PENALTY = 10
    CORRELATION_BOOST = 5
    CROSS_VALIDATED_BOOST = 5

    # Max-confidence caps by strongest evidence level.
    MAX_CONFIDENCE_START = 95
    CAP_EXPLOITED = 100
    CAP_VERIFIED = 90
    CAP_CONFIRMED = 85
    CAP_LIKELY = 75
    CAP_POSSIBLE = 60
    CAP_ERROR = 40

    _LEVEL_ORDER = ('unknown', 'not_tested', 'possible', 'likely',
                    'confirmed', 'verified', 'exploited')

    def compute(self, evidence_score: EvidenceScore,
                correlation_boost: int = 0,
                cross_validated: bool = False) -> ConfidenceResult:
        """Compute confidence for one finding.

        ``correlation_boost`` is the Confidence Engine's applied boost (0 for none;
        v2 parity uses +5 when the finding was correlation-escalated).
        ``cross_validated`` marks findings confirmed by multiple independent passes.
        """
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
            base = evidence_score.weighted_bonus // evidence_score.total_weight + self.BASE_ANCHOR
        else:
            base = self.BASE_ANCHOR

        if evidence_score.evidence_count >= 2 and not has_error:
            base += self.MULTIPLE_EVIDENCE_BONUS
            factors["Multiple Evidences"] = self.MULTIPLE_EVIDENCE_BONUS

        if len(verification_passes) >= 2:
            base += self.VERIFICATION_PASS_MULTI_BONUS
            factors["Multi-pass verification"] = self.VERIFICATION_PASS_MULTI_BONUS
        elif len(verification_passes) >= 1:
            base += self.VERIFICATION_PASS_SINGLE_BONUS
            factors["Verification pass"] = self.VERIFICATION_PASS_SINGLE_BONUS

        if has_cross_validation:
            base += self.CROSS_VALIDATION_BONUS
            factors["Cross-validation"] = self.CROSS_VALIDATION_BONUS

        # Max-confidence cap chain (order-preserving for exact v2 parity).
        max_confidence = self.MAX_CONFIDENCE_START
        has_exploited = False
        has_verified = False
        for level in evidence_score.level_sequence:
            if level == 'exploited':
                max_confidence = self.CAP_EXPLOITED
                has_exploited = True
            elif level == 'verified':
                if not has_exploited:
                    max_confidence = self.CAP_VERIFIED
                has_verified = True
            elif level == 'confirmed':
                if not has_exploited and not has_verified:
                    max_confidence = self.CAP_CONFIRMED
            elif level == 'likely':
                if not has_exploited and not has_verified and max_confidence > self.CAP_CONFIRMED:
                    max_confidence = self.CAP_LIKELY
            elif level == 'possible':
                if max_confidence > self.CAP_LIKELY:
                    max_confidence = self.CAP_POSSIBLE

        if has_error:
            max_confidence = min(max_confidence, self.CAP_ERROR)
            factors["Error detected"] = -self.ERROR_PENALTY

        if correlation_boost > 0:
            max_confidence = min(100, max_confidence + correlation_boost)
            factors["Correlation boost"] = correlation_boost

        if cross_validated:
            max_confidence = min(100, max_confidence + self.CROSS_VALIDATED_BOOST)
            factors["Cross-validated"] = self.CROSS_VALIDATED_BOOST

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
