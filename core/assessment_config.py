"""
Assessment Config v4.2 — single source of truth for duplicated engine constants.

Phase 4.1 audit (C8) found the same constants (confidence caps/bonuses, risk
weights/multipliers, severity maps, coverage penalties, verification bands)
defined in several files, with at least one already drifted. This module is the
ONE place they live. Engines import from here so a future calibration change is a
single edit and every engine stays in lockstep.

Parity contract: every value below is byte-identical to the pre-P4.2 defaults in
v4.9.0. P4.2 makes NO output change; this module exists to *prepare* calibration.

NOTE: values here are duplicated conceptually but intentionally not migrated yet
from engine-local constants to guarantee zero risk. Engines are updated to read
from this module one small step at a time under the zero-regression gates.
"""

from typing import Dict, Tuple

# Identifies the engineering-generation; used by the calibration flag/system to
# reject/acknowledge snapshots computed against a different numbers.
CALIBRATION_SCHEME = "v4.2-frozen"
CALIBRATED_SCHEME = "v4.3-calibrated"

# ---------------------------------------------------------------- Evidence Engine
EVIDENCE = {
    "LEVEL_QUALITY": {
        "exploited": 100,
        "verified": 90,
        "confirmed": 80,
        "likely": 65,
        "possible": 50,
        "unknown": 30,
        "not_tested": 10,
    },
    "LEVEL_ORDER": ("unknown", "not_tested", "possible", "likely",
                    "confirmed", "verified", "exploited"),
    "PAYLOAD_BONUS": 5,
    "PARAMETER_BONUS": 2,
    "RAW_SNIPPET_BONUS": 3,
    "RAW_HEADERS_BONUS": 2,
    "RAW_TIMING_BONUS": 2,
    "RAW_REQUEST_RESPONSE_BONUS": 3,
    "VERIFICATION_PASS_BONUS": 5,
    "VERIFICATION_PASS_MAX": 10,
    "ERROR_PENALTY": 20,
    "CONTRADICTION_PENALTY": 10,
    # (raw_data key, bonus) used for evidence-quality riding.
    "RAW_KEYS_BONUS": (
        ("snippet", 3),
        ("headers", 2),
        ("timing", 2),
        ("request", 3),
    ),
}

# ------------------------------------------------------------------ Confidence Engine
CONFIDENCE = {
    "BASE_ANCHOR": 50,
    "MULTIPLE_EVIDENCE_BONUS": 5,
    "VERIFICATION_PASS_SINGLE_BONUS": 5,
    "VERIFICATION_PASS_MULTI_BONUS": 10,
    "CROSS_VALIDATION_BONUS": 10,
    "ERROR_PENALTY": 10,
    "CORRELATION_BOOST": 5,
    "CROSS_VALIDATED_BOOST": 5,
    "MAX_CONFIDENCE_START": 95,
    "CAP_EXPLOITED": 100,
    "CAP_VERIFIED": 90,
    "CAP_CONFIRMED": 85,
    "CAP_LIKELY": 75,
    "CAP_POSSIBLE": 60,
    "CAP_ERROR": 40,
    "LEVEL_ORDER": ("unknown", "not_tested", "possible", "likely",
                    "confirmed", "verified", "exploited"),
}

# ------------------------------------------------------------------ Confidence (P4.3 calibration)
# Normalized confidence profile. ACTIVE ONLY WHEN core.feature_flags.enabled()
# is True (SEA_CALIBRATION=report|on). When the flag is off, the engines use the
# frozen CONFIDENCE dict above so default runs remain byte-identical to v4.9.0.
#
# Reconciliation vs the frozen v4.2 profile (audit findings C1/C2/C3):
#   - CAP_VERIFIED  90 -> 95  : verified evidence can now reach the verification
#                               'confirmed' band (>=95); previously capped below it.
#   - CAP_CONFIRMED 85 -> 95  : confirmed evidence can reach the 'confirmed'
#                               verification band instead of stalling at 'likely'.
#   - CAP_LIKELY    75 -> 80  : aligned with the LIKELY verification threshold (80)
#                               so likely evidence classifies as 'likely' (not 'possible').
#   - CAP_POSSIBLE  60 -> 55  : aligned with the POSSIBLE verification threshold (55).
#   - CAP_EXPLOITED/ERROR     : unchanged (100 / 40).
#   - EVIDENCE_QUALITY_WEIGHT : evidence_quality (currently unused by v4.2) is blended
#                               into the confidence base so rich evidence (payload +
#                               snippet + verification passes) lifts confidence, and
#                               weak/error evidence pulls it down (audit C2).
CALIBRATED_CONFIDENCE = {
    "BASE_ANCHOR": 50,
    "MULTIPLE_EVIDENCE_BONUS": 5,
    "VERIFICATION_PASS_SINGLE_BONUS": 5,
    "VERIFICATION_PASS_MULTI_BONUS": 10,
    "CROSS_VALIDATION_BONUS": 10,
    "ERROR_PENALTY": 10,
    "CORRELATION_BOOST": 5,
    "CROSS_VALIDATED_BOOST": 5,
    "MAX_CONFIDENCE_START": 95,
    "CAP_EXPLOITED": 100,
    "CAP_VERIFIED": 95,
    "CAP_CONFIRMED": 95,
    "CAP_LIKELY": 80,
    "CAP_POSSIBLE": 55,
    "CAP_ERROR": 40,
    # Blend weight for evidence_quality in the calibrated base (0..1).
    # 1.0 = evidence_quality directly replaces the legacy base when it is higher,
    # so the currently-unused evidence_quality signal (C2) directly lifts confidence.
    # Legacy bonuses (multiple evidence, verification passes, cross-validation) still
    # stack on top, preserving monotonicity.
    "EVIDENCE_QUALITY_WEIGHT": 1.0,
    "LEVEL_ORDER": ("unknown", "not_tested", "possible", "likely",
                    "confirmed", "verified", "exploited"),
}
VERIFICATION = {
    "CONFIRMED_THRESHOLD": 95,
    "LIKELY_THRESHOLD": 80,
    "POSSIBLE_THRESHOLD": 55,
    "MANUAL_REVIEW_THRESHOLD": 35,
    "LABELS": {
        "confirmed": "Confirmed",
        "likely": "Likely",
        "possible": "Possible",
        "manual_review": "Manual Review",
        "unverified": "Unverified",
    },
    # internal v3 band -> v2 report vocabulary.
    "REPORT_MAP": {"confirmed": "verified"},
}

# --------------------------------------------------------------------- Severity Engine
SEVERITY = {
    "SCORE": {  # CVSS base per severity (v2 parity)
        "none": 0.0,
        "info": 1.0,
        "low": 3.0,
        "medium": 5.0,
        "high": 7.0,
        "critical": 9.0,
    },
    "IMPACT_MULTIPLIER": {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.6,
        "low": 0.4,
        "info": 0.2,
        "none": 0.2,
    },
    "VERIFIED_STATUSES": ("confirmed", "verified", "likely"),
    "SEVERITY_ORDER": ("none", "info", "low", "medium", "high", "critical"),
}

# -------------------------------------------------------------------------- Risk Engine
RISK = {
    "SEVERITY_WEIGHTS": {
        "critical": 10,
        "high": 7,
        "medium": 5,
        "low": 3,
        "info": 1,
        "none": 0,
    },
    # Confidence bands map: v2 'verified' + v3 'confirmed' both 1.0.
    "VERIFICATION_MULTIPLIERS": {
        "confirmed": 1.0,
        "verified": 1.0,
        "likely": 0.85,
        "possible": 0.6,
        "manual_review": 0.4,
        "unverified": 0.3,
    },
    # Warnings are NOT vulnerabilities and must not move the risk score toward
    # the vulnerability severity scale. They contribute a small, bounded,
    # per-warning "load" (SOP Issue #5: ~0.5 points each, so 4 warnings ~ 2%),
    # excluded from the max_possible denominator so they can never dominate the
    # score of a scan with zero confirmed vulnerabilities.
    "WARNING_UNIT": 0.5,
    "WARNING_LOAD_CAP": 15.0,
    "OCCURRENCE_FLOOR": 0.8,
    "OCCURRENCE_SCALE": 0.2,
    "MAX_OCCURRENCE_CAP": 5,
    "GRADE_BANDS": (
        (5.0, "A+"), (10.0, "A"), (20.0, "B+"), (30.0, "B"),
        (40.0, "C+"), (50.0, "C"), (65.0, "D+"), (80.0, "D"),
    ),
    "GRADE_F": "F",
}

# ---------------------------------------------------------------- Coverage Engine
COVERAGE = {
    "EXECUTION_STATE_LABELS": None,  # comes from finding.EXECUTION_STATE_LABELS
    "FAILED_PENALTY": 15,
    "SKIPPED_PENALTY": 8,
    "NOT_APPLICABLE_PENALTY": 4,
    "CONFIDENCE_IMPACT_SCALE": 5,
}

# ----------------------------------------------------------------- Assessment Engine
ASSESSMENT = {
    "SKIPPED_CONFIDENCE_PENALTY": 6,
    "FAILED_CONFIDENCE_PENALTY": 10,
    "COVERAGE_QUALITY_FLOOR": 30,
    "COVERAGE_PENALTY_SCALE": 0.5,
    "VERIFIED_BONUS": 5,
    "UNVERIFIED_PENALTY": 10,
    "VERIFIED_STATUSES": ("confirmed", "verified", "likely"),
    "UNVERIFIED_STATUSES": ("possible", "manual_review", "unverified"),
}

# ------------------------------------------------------------------ Correlation Engine
CORRELATION = {
    "SEVERITY_ORDER": ("none", "info", "low", "medium", "high", "critical"),
}


# Public helpers so engines/consumers keep a uniform access pattern.

def severity_score(value: str) -> float:
    return SEVERITY["SCORE"].get(value, 0.0)


def severity_weight(value: str) -> int:
    return RISK["SEVERITY_WEIGHTS"].get(value, 1)


def verification_multiplier(status: str) -> float:
    return RISK["VERIFICATION_MULTIPLIERS"].get(status, 0.3)