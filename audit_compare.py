import os, json
from tests.corpus import scenario_names, build_scenario
from core.pipeline import run_assessment_pipeline
from datetime import datetime


def run(flag):
    if flag:
        os.environ["SEA_CALIBRATION"] = "report"
    else:
        os.environ.pop("SEA_CALIBRATION", None)
    import importlib
    import core.confidence_engine as ce; importlib.reload(ce)
    import core.feature_flags as ff; importlib.reload(ff)

    rows = {}
    for name in scenario_names():
        sr = build_scenario(name)
        sr.total_modules = sr.total_modules or len(sr.findings)
        sr.start_time = datetime.now(); sr.end_time = sr.start_time
        a = run_assessment_pipeline(sr)
        vulns = sr.get_vulnerabilities()
        warnings = sr.get_warning_findings()
        rows[name] = {
            "risk": int(a.statistics.get("risk_score", 0)),
            "tier": a.overall_tier,
            "severity": a.overall_severity,
            "conf": a.assessment_confidence,
            "cov_pct": a.coverage.coverage_percent,
            "vulns": len(vulns),
            "warn": len(warnings),
            "verified": a.summary.verified_count,
            "likely": a.summary.likely_count,
            "review": a.summary.requires_review_count,
            "prose": a.summary.prose,
            "keys": a.summary.key_findings,
            "conf_factors": dict(a.assessment_confidence_factors),
            "reasons": list(a.overall_reasons),
            "highlights": list(a.summary.positive_highlights),
            "actions": a.summary.action_priority,
        }
    return rows

before = run(False)
after = run(True)

for name in scenario_names():
    b, a = before[name], after[name]
    print("=" * 70)
    print(f"[{name}]")
    changed = []
    for k in ("risk", "tier", "severity", "conf", "warn"):
        if b[k] != a[k]:
            changed.append(f"{k}: {b[k]} -> {a[k]}")
    if changed:
        print("  CHANGED:", "; ".join(changed))
    else:
        print("  (unchanged)")
    print(f"  prose_before: {b['prose']}")
    if b['prose'] != a['prose']:
        print(f"  prose_after : {a['prose']}")
    if b['conf_factors'] != a['conf_factors']:
        print(f"  factors_before: {b['conf_factors']}")
        print(f"  factors_after : {a['conf_factors']}")
    if b['reasons'] != a['reasons']:
        print(f"  reasons_before: {b['reasons']}")
        print(f"  reasons_after : {a['reasons']}")

json.dump({"before": before, "after": after},
          open("tests/fixtures/calibration/assessment_comparison_raw.json", "w", encoding="utf-8"),
          indent=2, default=str)
print("\nraw dump written")