"""
Engine execution paths for the regression harness.

``run_v2`` reproduces the archived v2 pipeline (tests/v2_reference.py):
  v2_decide() per finding -> run_correlation() -> get_statistics().

``run_v3`` runs the single production pipeline:
  run_assessment_pipeline() (Evidence -> Confidence -> Verification -> Severity
  per finding, then correlation payloads, Risk, Coverage, Assessment).

Both return the same comparable snapshot shape.
"""

from typing import Any, Dict

from tests.corpus import build_scenario


def _snapshot(sr: Any, stats: Dict[str, Any]) -> Dict[str, Any]:
    states = {
        d['module']: d['state']
        for d in stats.get('execution_states', {}).get('details', [])
    }
    findings = []
    for f in sr.findings:
        findings.append({
            'module': f.module,
            'status': f.status.value if hasattr(f.status, 'value') else str(f.status),
            'severity': f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            'confidence': f.confidence,
            'verification': f.verification_status or 'unverified',
            'cvss_score': f.cvss_score,
            'execution_state': states.get(f.module, 'unknown'),
        })
    return {
        'findings': findings,
        'stats': stats,
        'coverage': {
            'total': stats['coverage_total'],
            'executed': stats['coverage_executed'],
            'skipped': stats['coverage_skipped'],
            'failed': stats['coverage_failed'],
            'not_applicable': stats['coverage_not_applicable'],
            'percent': stats['coverage_percentage'],
        },
        'overall': {
            'tier': stats['overall_tier'],
            'label': stats['overall_severity'],
            'reasons': list(stats['overall_reasons']),
        },
        'risk_score': stats['risk_score'],
        'risk_grade': stats['risk_breakdown']['security_grade'],
        'verified_vulns': stats['verified_vulns'],
        'likely_vulns': stats['likely_vulns'],
        'correlations_found': stats['correlations_found'],
    }


def run_v2(scenario_name: str) -> Dict[str, Any]:
    from tests.v2_reference import v2_decide

    sr = build_scenario(scenario_name)
    for f in sr.findings:
        v2_decide(f)
    sr.run_correlation()
    stats = sr.get_statistics()
    return _snapshot(sr, stats)


def run_v3(scenario_name: str) -> Dict[str, Any]:
    from core.pipeline import run_assessment_pipeline

    sr = build_scenario(scenario_name)
    assessment = run_assessment_pipeline(sr)
    return _snapshot(sr, assessment.statistics)


def run_v2_on(sr: Any) -> Dict[str, Any]:
    """Archived v2 path over an already-built ScanResult (used by the live runner)."""
    from tests.v2_reference import v2_decide

    for f in sr.findings:
        v2_decide(f)
    sr.run_correlation()
    stats = sr.get_statistics()
    return _snapshot(sr, stats)


def run_v3_on(sr: Any) -> Dict[str, Any]:
    """Single v3 path over an already-built ScanResult (used by the live runner)."""
    from core.pipeline import run_assessment_pipeline

    assessment = run_assessment_pipeline(sr)
    return _snapshot(sr, assessment.statistics)
