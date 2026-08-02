"""
Assessment Model v3.0 — the single output contract of the engine pipeline.

All engines produce typed results defined here and the Assessment Engine assembles
the final immutable Assessment. No output interface (GUI, CLI, HTML, PDF, JSON)
recomputes scores; they consume Assessment / its pipeline results only.

See docs/ENGINE_ARCHITECTURE_V3.md for the full specification.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Optional


# ===== Inter-engine pipeline results =====

@dataclass(frozen=True)
class EvidenceScore:
    """Output of the Evidence Engine; consumed by the Confidence Engine.

    ``weighted_bonus`` / ``total_weight`` follow the v2.x Finding logic exactly:
    only positive ``confidence_bonus`` entries contribute, so Phase B parity is
    preserved (weighted_bonus = sum(bonus*weight), total_weight = sum(weight)).

    ``bonus_factors`` carries the per-evidence positive bonus map (used to rebuild
    v2-style confidence_factors). ``level_sequence`` preserves evidence level order,
    required to reproduce the v2 max-confidence cap chain exactly.
    """
    evidence_count: int
    evidence_quality: int = 0
    weighted_bonus: int = 0
    total_weight: int = 0
    verification_passes: frozenset = field(default_factory=frozenset)
    has_cross_validation: bool = False
    has_error: bool = False
    strongest_level: str = "unknown"
    factors: Dict[str, int] = field(default_factory=dict)
    bonus_factors: Dict[str, int] = field(default_factory=dict)
    level_sequence: tuple = field(default_factory=tuple)


@dataclass(frozen=True)
class ConfidenceResult:
    """Output of the Confidence Engine."""
    confidence: int = 0
    factors: Dict[str, int] = field(default_factory=dict)
    explanation: str = ""
    verification_passes: int = 0
    cross_validated: bool = False


@dataclass(frozen=True)
class VerificationClassification:
    """Output of the Verification Engine (finding classification, not HTTP verification)."""
    status: str = "unverified"
    label: str = "Unverified"
    explanation: str = ""


@dataclass(frozen=True)
class SeverityResult:
    """Output of the Severity Engine."""
    severity: str = "none"
    exploitability: str = "unknown"
    impact: Dict[str, int] = field(default_factory=lambda: {
        'confidentiality': 0,
        'integrity': 0,
        'availability': 0,
    })
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cvss_explanation: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    capec_id: str = ""
    mitre_id: str = ""
    asvs_reference: str = ""


@dataclass(frozen=True)
class RiskResult:
    """Output of the Risk Engine.

    ``risk_score`` is the numeric score rounded to one decimal (e.g. 17.0), matching
    the v2.x statistics dict. Display consumers truncate to int (Assessment.overall_score).
    """
    risk_score: float = 0.0
    security_grade: str = "A+"
    total_weighted: float = 0.0
    max_possible: float = 0.0
    breakdown: List[Dict[str, Any]] = field(default_factory=list)
    explanation: List[str] = field(default_factory=list)
    summary: str = ""
    vulnerability_count: int = 0
    warning_count: int = 0
    calculation_formula: str = ""


@dataclass(frozen=True)
class CoverageReport:
    """Output of the Coverage Engine (see docs §6.4)."""
    total: int = 0
    executed: int = 0
    passed: int = 0
    failed: int = 0
    warning: int = 0
    info: int = 0
    skipped: int = 0
    not_applicable: int = 0
    coverage_percent: int = 0
    coverage_quality: int = 0
    execution_states: Dict[str, Any] = field(default_factory=dict)
    skip_reasons: Dict[str, List[str]] = field(default_factory=dict)
    explanation: str = ""
    assessment_confidence_impact: int = 0


# ===== Narrative =====

@dataclass(frozen=True)
class ExecutiveSummary:
    """Natural-language summary produced by the Executive Summary Generator."""
    prose: str = ""
    key_findings: List[str] = field(default_factory=list)
    positive_highlights: List[str] = field(default_factory=list)
    coverage_statement: str = ""
    action_priority: List[str] = field(default_factory=list)
    verified_count: int = 0
    likely_count: int = 0
    requires_review_count: int = 0


# ===== Assessment content =====

@dataclass(frozen=True)
class FindingAssessment:
    """One assessed module result, derived from a raw Finding + engine outputs."""
    module: str = ""
    title: str = ""
    status: str = "unknown"
    execution_state: str = "skipped"
    execution_reason: str = ""
    severity: str = "none"
    confidence: int = 0
    confidence_factors: Dict[str, int] = field(default_factory=dict)
    confidence_explanation: str = ""
    verification: str = "unverified"
    evidence_quality: int = 0
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cvss_explanation: str = ""
    exploitability: str = "unknown"
    impact: Dict[str, int] = field(default_factory=lambda: {
        'confidentiality': 0,
        'integrity': 0,
        'availability': 0,
    })
    cwe_id: str = ""
    owasp_category: str = ""
    capec_id: str = ""
    mitre_id: str = ""
    asvs_reference: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    risk_contribution: float = 0.0
    timestamps: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Assessment:
    """The immutable, single output of the assessment pipeline.

    ``statistics`` mirrors the v2.x ``ScanResult.get_statistics()`` dict so that
    Reporter, PDF reporter, Jinja2 templates and the GUI keep working unchanged.
    ``to_dict()`` additionally exposes the full v3 structure under the top level.
    """
    scan_id: str = ""
    target: str = ""
    target_host: str = ""
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0

    overall_score: int = 0
    overall_severity: str = "none"
    overall_tier: str = "none"
    overall_label: str = "No Risk"
    overall_description: str = ""
    overall_color: str = "#2196F3"
    overall_reasons: List[str] = field(default_factory=list)

    assessment_confidence: int = 0
    assessment_confidence_factors: Dict[str, int] = field(default_factory=dict)
    assessment_confidence_explanation: str = ""

    coverage: CoverageReport = field(default_factory=CoverageReport)
    summary: ExecutiveSummary = field(default_factory=ExecutiveSummary)
    findings: List[FindingAssessment] = field(default_factory=list)
    modules: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "target_host": self.target_host,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "overall_score": self.overall_score,
            "overall_severity": self.overall_severity,
            "overall_tier": self.overall_tier,
            "overall_label": self.overall_label,
            "overall_description": self.overall_description,
            "overall_color": self.overall_color,
            "overall_reasons": list(self.overall_reasons),
            "assessment_confidence": self.assessment_confidence,
            "assessment_confidence_factors": dict(self.assessment_confidence_factors),
            "assessment_confidence_explanation": self.assessment_confidence_explanation,
            "coverage": {
                "total": self.coverage.total,
                "executed": self.coverage.executed,
                "passed": self.coverage.passed,
                "failed": self.coverage.failed,
                "warning": self.coverage.warning,
                "info": self.coverage.info,
                "skipped": self.coverage.skipped,
                "not_applicable": self.coverage.not_applicable,
                "coverage_percent": self.coverage.coverage_percent,
                "coverage_quality": self.coverage.coverage_quality,
                "execution_states": self.coverage.execution_states,
                "skip_reasons": self.coverage.skip_reasons,
                "explanation": self.coverage.explanation,
                "assessment_confidence_impact": self.coverage.assessment_confidence_impact,
            },
            "summary": {
                "prose": self.summary.prose,
                "key_findings": list(self.summary.key_findings),
                "positive_highlights": list(self.summary.positive_highlights),
                "coverage_statement": self.summary.coverage_statement,
                "action_priority": list(self.summary.action_priority),
                "verified_count": self.summary.verified_count,
                "likely_count": self.summary.likely_count,
                "requires_review_count": self.summary.requires_review_count,
            },
            "findings": [f.__dict__ for f in self.findings],
            "modules": dict(self.modules),
            "statistics": self.statistics,
            "metadata": dict(self.metadata),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, default=str)
