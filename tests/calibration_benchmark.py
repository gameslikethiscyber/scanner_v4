"""
Calibration benchmark — Before (flag OFF / default) vs After (flag ON / calibrated)
confidence comparison across all canonical scenarios.

Usage:
    python -m tests.calibration_benchmark [--show] [--out PATH]

Output: JSON with before/after for each scenario, plus summary stats.
"""

import argparse
import json
import os
import sys

# Run before (flag OFF)
os.environ.pop("SEA_CALIBRATION", None)
import core.feature_flags as _ff
# Force fresh import of confidence engine so it sees the flag correctly
# (re-import necessary since confidence_engine reads _ff at import time via _profile)
import importlib
import core.confidence_engine
importlib.reload(core.confidence_engine)

from core.pipeline import run_engine_pipeline, run_assessment_pipeline
from tests.calibration_capture import scenarios, build_scan_result

from datetime import datetime


def run_all(flag_set: str):
    """Run all canonical scenarios under the given flag state.
    Returns (per_finding_dict, scan_dict).
    """
    if flag_set == "on":
        os.environ["SEA_CALIBRATION"] = "report"
    else:
        os.environ.pop("SEA_CALIBRATION", None)
    # Reload so confidence_engine._profile() picks up new flag
    importlib.reload(core.confidence_engine)
    importlib.reload(_ff)

    items = scenarios()
    findings_out = {}
    for name, f in items:
        run_engine_pipeline(f)
        findings_out[name] = {
            "confidence": f.confidence,
            "status": f.status.value,
            "verification_status": f.verification_status,
            "verification_class": f.verification_class,
            "severity": f.severity.value,
            "evidence_quality": f.evidence_quality,
        }

    sr = build_scan_result(items)
    sr.start_time = datetime.now()
    sr.end_time = sr.start_time
    assessment = run_assessment_pipeline(sr)
    stats = dict(assessment.statistics)
    scan_out = {
        "risk_score": stats.get("risk_score"),
        "overall_tier": assessment.overall_tier,
        "assessment_confidence": assessment.assessment_confidence,
        "coverage_percent": assessment.coverage.coverage_percent,
        "vulnerabilities": stats.get("vulnerabilities"),
    }
    return findings_out, scan_out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--out", default="tests/fixtures/calibration/calibration_benchmark.json")
    args = ap.parse_args()

    before_f, before_scan = run_all("off")
    after_f, after_scan = run_all("on")

    summary = {
        "scheme": "v4.3-calibrated",
        "generated_by": "tests/calibration_benchmark.py",
        "before": {"per_finding": before_f, "scan": before_scan},
        "after": {"per_finding": after_f, "scan": after_scan},
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    if args.show:
        print("=== BEFORE (flag OFF) ===")
        print(json.dumps(before_f, indent=2))
        print("scan:", json.dumps(before_scan, indent=2))
        print("\n=== AFTER (flag ON) ===")
        print(json.dumps(after_f, indent=2))
        print("scan:", json.dumps(after_scan, indent=2))
        print("\n=== DELTA ===")
        for name in before_f:
            b = before_f[name]
            a = after_f[name]
            if b["confidence"] != a["confidence"]:
                print(f"  {name}: {b['confidence']} -> {a['confidence']} confidence "
                      f"(verification: {b['verification_status']} -> {a['verification_status']})")
        b_r = before_scan.get("risk_score", 0)
        a_r = after_scan.get("risk_score", 0)
        if b_r != a_r:
            print(f"  scan risk_score: {b_r} -> {a_r}")
        b_c = before_scan.get("assessment_confidence", 0)
        a_c = after_scan.get("assessment_confidence", 0)
        if b_c != a_c:
            print(f"  scan assessment_confidence: {b_c} -> {a_c}")

    print(f"wrote calibration benchmark -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())