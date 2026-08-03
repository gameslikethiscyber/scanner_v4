import os, json
os.environ.pop("SEA_CALIBRATION", None)
from tests.corpus import scenario_names, build_scenario
from core.pipeline import run_assessment_pipeline
from datetime import datetime

rows = []
for name in scenario_names():
    sr = build_scenario(name)
    sr.total_modules = sr.total_modules or len(sr.findings)
    sr.start_time = datetime.now(); sr.end_time = sr.start_time
    a = run_assessment_pipeline(sr)
    vulns = sr.get_vulnerabilities()
    warnings = sr.get_warning_findings()
    vverified = sum(1 for f in vulns if f.verification_status == "verified")
    vlikely = sum(1 for f in vulns if f.verification_status == "likely")
    rows.append({
        "scenario": name,
        "risk": int(a.statistics.get("risk_score", 0)),
        "tier": a.overall_tier,
        "severity": a.overall_severity,
        "conf": a.assessment_confidence,
        "cov_pct": a.coverage.coverage_percent,
        "quality": a.coverage.coverage_quality,
        "vulns": len(vulns),
        "warn": len(warnings),
        "verified": vverified,
        "likely": vlikely,
        "prose": a.summary.prose,
        "keys": a.summary.key_findings,
        "actions": a.summary.action_priority,
        "conf_factors": dict(a.assessment_confidence_factors),
        "reasons": list(a.overall_reasons),
    })

print(json.dumps(rows, indent=2, default=str))