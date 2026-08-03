"""
Evidence Engine v3.0 — single owner of evidence normalisation and quality scoring.

Scanners only collect raw evidence; this engine turns it into an EvidenceScore
consumed by the Confidence Engine. It never mutates findings.

See docs/ENGINE_ARCHITECTURE_V3.md §5.1 and §6.
"""

import logging
from typing import Any, Dict, List, Optional, Union

from core.assessment import EvidenceScore
from core.assessment_config import EVIDENCE
from core.evidence import Evidence, EvidenceLevel, EvidenceType

logger = logging.getLogger('SeaScanner.EvidenceEngine')


class EvidenceEngine:
    """Normalises raw evidence and computes its quality / confidence inputs."""

    # Level base quality scores (0-100). Rationale: exploited evidence is the
    # strongest possible proof; verified evidence is independently confirmed;
    # lower levels indicate increasing uncertainty.
    LEVEL_QUALITY = dict(EVIDENCE["LEVEL_QUALITY"])

    # Ordering used to pick the strongest evidence level in a finding.
    _LEVEL_ORDER = tuple(EVIDENCE["LEVEL_ORDER"])

    # Quality adjustments (additive, each recorded in factors for auditability).
    PAYLOAD_BONUS = EVIDENCE["PAYLOAD_BONUS"]
    PARAMETER_BONUS = EVIDENCE["PARAMETER_BONUS"]
    RAW_SNIPPET_BONUS = EVIDENCE["RAW_SNIPPET_BONUS"]
    RAW_HEADERS_BONUS = EVIDENCE["RAW_HEADERS_BONUS"]
    RAW_TIMING_BONUS = EVIDENCE["RAW_TIMING_BONUS"]
    RAW_REQUEST_RESPONSE_BONUS = EVIDENCE["RAW_REQUEST_RESPONSE_BONUS"]
    VERIFICATION_PASS_BONUS = EVIDENCE["VERIFICATION_PASS_BONUS"]
    VERIFICATION_PASS_MAX = EVIDENCE["VERIFICATION_PASS_MAX"]
    ERROR_PENALTY = EVIDENCE["ERROR_PENALTY"]
    CONTRADICTION_PENALTY = EVIDENCE["CONTRADICTION_PENALTY"]

    _RAW_KEYS_BONUS = tuple(EVIDENCE["RAW_KEYS_BONUS"])

    def score(self, evidence: Optional[List[Any]] = None,
              correlation_evidence: Optional[List[Any]] = None) -> EvidenceScore:
        """Score a finding's raw evidence (and optional correlation evidence).

        Returns an EvidenceScore whose weighted_bonus/total_weight reproduce the
        v2.x Finding logic so the Confidence Engine can match legacy numbers.
        """
        ev_list: List[Evidence] = []
        for item in (evidence or []):
            ev = self._coerce(item)
            if ev is not None:
                ev_list.append(ev)
        for item in (correlation_evidence or []):
            ev = self._coerce(item)
            if ev is not None:
                ev_list.append(ev)

        weighted_bonus = 0
        total_weight = 0
        factors: Dict[str, int] = {}
        bonus_factors: Dict[str, int] = {}
        verification_passes = set()
        has_cross_validation = False
        has_error = False
        level_sequence: List[str] = []

        for ev in ev_list:
            desc = (getattr(ev, 'description', '') or '')[:30]
            bonus = int(getattr(ev, 'confidence_bonus', 0) or 0)
            weight = int(getattr(ev, 'weight', 1) or 0)
            level = self._level_value(ev)
            etype = getattr(ev, 'type', None)
            etype_value = getattr(etype, 'value', etype) or ''
            vpass = int(getattr(ev, 'verification_pass', 0) or 0)

            level_sequence.append(getattr(level, 'value', 'unknown') or 'unknown')
            if etype_value == 'cross_validation':
                has_cross_validation = True
            if vpass > 0:
                verification_passes.add(vpass)
            if level is EvidenceLevel.UNKNOWN and 'error' in (getattr(ev, 'description', '') or '').lower():
                has_error = True

            # v2.x parity: only positive bonuses contribute to the confidence base.
            if bonus > 0:
                weighted_bonus += bonus * weight
                total_weight += weight
                bonus_factors[f"Evidence: {desc}"] = bonus

        evidence_count = len(ev_list)
        strongest = self._strongest_level(ev_list)
        quality_factors: Dict[str, int] = {}
        if evidence_count == 0:
            return EvidenceScore(
                evidence_count=0,
                evidence_quality=0,
                weighted_bonus=0,
                total_weight=0,
                verification_passes=frozenset(),
                has_cross_validation=False,
                has_error=False,
                strongest_level="unknown",
                factors={},
                bonus_factors={},
                level_sequence=(),
            )
        evidence_quality = self.LEVEL_QUALITY.get(strongest, 30)

        if any(getattr(ev, 'payload', None) for ev in ev_list):
            evidence_quality += self.PAYLOAD_BONUS
            quality_factors["Quality: payload"] = self.PAYLOAD_BONUS
        if any(getattr(ev, 'parameter', None) for ev in ev_list):
            evidence_quality += self.PARAMETER_BONUS
            quality_factors["Quality: parameter"] = self.PARAMETER_BONUS

        for key, bonus in self._RAW_KEYS_BONUS:
            if any(self._has_raw(ev, key) for ev in ev_list):
                evidence_quality += bonus
                quality_factors[f"Quality: raw_{key}"] = bonus

        pass_bonus = min(len(verification_passes) * self.VERIFICATION_PASS_BONUS,
                         self.VERIFICATION_PASS_MAX)
        if pass_bonus > 0:
            evidence_quality += pass_bonus
            quality_factors["Quality: verification passes"] = pass_bonus

        if has_error:
            evidence_quality -= self.ERROR_PENALTY
            factors["Error detected"] = -self.ERROR_PENALTY
            positive = (EvidenceLevel.EXPLOITED, EvidenceLevel.VERIFIED,
                        EvidenceLevel.CONFIRMED, EvidenceLevel.LIKELY)
            if any(self._level_value(ev) in positive for ev in ev_list):
                evidence_quality -= self.CONTRADICTION_PENALTY
                factors["Contradictory evidence"] = -self.CONTRADICTION_PENALTY

        evidence_quality = max(0, min(100, evidence_quality))
        quality_factors["Quality: strongest level"] = self.LEVEL_QUALITY.get(strongest, 30)
        factors.update(quality_factors)

        return EvidenceScore(
            evidence_count=evidence_count,
            evidence_quality=evidence_quality,
            weighted_bonus=weighted_bonus,
            total_weight=total_weight,
            verification_passes=frozenset(verification_passes),
            has_cross_validation=has_cross_validation,
            has_error=has_error,
            strongest_level=strongest,
            factors=factors,
            bonus_factors=bonus_factors,
            level_sequence=tuple(level_sequence),
        )

    @staticmethod
    def _coerce(item: Any) -> Optional[Evidence]:
        """Normalise an Evidence instance, a dict, or an Evidence-like object."""
        if isinstance(item, Evidence):
            return item
        if isinstance(item, dict):
            description = str(item.get('description', ''))
            level = item.get('level', EvidenceLevel.POSSIBLE)
            if isinstance(level, str):
                try:
                    level = EvidenceLevel(level)
                except ValueError:
                    level = EvidenceLevel.POSSIBLE
            etype = item.get('type', EvidenceType.RESPONSE_ANALYSIS)
            if isinstance(etype, str):
                try:
                    etype = EvidenceType(etype)
                except ValueError:
                    etype = EvidenceType.RESPONSE_ANALYSIS
            known = {'payload', 'endpoint', 'parameter', 'method', 'timestamp',
                     'raw_data', 'confidence_bonus', 'weight',
                     'verification_pass', 'verification_method'}
            kwargs = {k: v for k, v in item.items() if k in known}
            try:
                return Evidence(level=level, type=etype, description=description, **kwargs)
            except TypeError:
                return Evidence(level=level, type=etype, description=description)
        # Evidence-like object (has required attributes); scoring uses getattr.
        if all(hasattr(item, attr) for attr in ('level', 'type', 'description')):
            return item
        return None

    @staticmethod
    def _level_value(ev: Any) -> Optional[EvidenceLevel]:
        level = getattr(ev, 'level', None)
        if level is None:
            return None
        if isinstance(level, EvidenceLevel):
            return level
        try:
            return EvidenceLevel(level)
        except Exception:
            return None

    @classmethod
    def _strongest_level(cls, ev_list: List[Evidence]) -> str:
        best = "unknown"
        for ev in ev_list:
            level = cls._level_value(ev)
            raw = getattr(level, 'value', None) or str(level or 'unknown').lower()
            if raw in cls._LEVEL_ORDER and cls._LEVEL_ORDER.index(raw) > cls._LEVEL_ORDER.index(best):
                best = raw
        return best

    @staticmethod
    def _has_raw(ev: Any, key: str) -> bool:
        raw = getattr(ev, 'raw_data', None) or {}
        if isinstance(raw, dict):
            return bool(raw.get(key))
        return False
