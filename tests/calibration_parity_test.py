"""
Calibration parity guard (P4.2).

Recomputes the canonical scenarios through the real pipeline and asserts the
resulting confidence/status/severity/cvss/scan numbers are byte-identical to the
frozen parity baseline. Any P4.3+ change that alters a consumer-visible number
fails here until a reviewed snapshot diff is applied.

Usage:
    python -m tests.calibration_parity_test [--baseline PATH]
Exit 0 if parity holds.
"""

import argparse
import json
import os

from core.pipeline import run_engine_pipeline, run_assessment_pipeline
from tests.calibration_capture import build_scan_result, scenarios


def _compute():
    items = scenarios()

    findings_out = {}
    for name, f in items:
        run_engine_pipeline(f)
        findings_out[name] = {
            "module": f.module,
            "status": f.status.value,
            "confidence": f.confidence,
            "verification_status": f.verification_status,
            "verification_class": f.verification_class,
            "severity": f.severity.value,
            "cvss_score": f.cvss_score,
            "execution_state": f.execution_state.value if f.execution_state else None,
            "evidence_quality": f.evidence_quality,
        }

    sr = build_scan_result(items)
    assessment = run_assessment_pipeline(sr)
    stats = dict(assessment.statistics)
    scan_out = {
        "risk_score": stats.get("risk_score"),
        "overall_tier": assessment.overall_tier,
        "assessment_confidence": assessment.assessment_confidence,
        "coverage_percent": assessment.coverage.coverage_percent,
        "vulnerabilities": stats.get("vulnerabilities"),
    }
    return {"per_finding": findings_out, "scan": scan_out}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline",
                    default="tests/fixtures/calibration/parity_baseline.json")
    args = ap.parse_args()

    if not os.path.exists(args.baseline):
        print(f"ERROR: missing baseline {args.baseline}. Run "
              "`python -m tests.calibration_capture` first.")
        return 1

    with open(args.baseline, encoding="utf-8") as fh:
        baseline = json.load(fh)

    current = _compute()
    if baseline["per_finding"] == current["per_finding"] and \
            baseline["scan"] == current["scan"]:
        print("PARITY=0  calibration output matches frozen baseline.")
        return 0

    print("PARITY MISMATCH — consumer-visible number drifted from baseline.")
    print("Scan delta:", _diff(baseline["scan"], current["scan"]))
    print("Finding deltas:")
    for name in baseline["per_finding"]:
        d = _diff(baseline["per_finding"].get(name, {}),
                  current["per_finding"].get(name, {}))
        if d:
            print(f"  {name}: {d}")
    return 1


def _diff(a, b):
    d = {}
    for k in set(a) | set(b):
        if a.get(k) != b.get(k):
            d[k] = (a.get(k), b.get(k))
    return d


if __name__ == "__main__":
    raise SystemExit(main())