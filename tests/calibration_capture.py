"""
Calibration parity capture (P4.2).

Builds deterministic canonical findings, drives the real v4.2 pipeline
(Evidence -> Confidence -> Verification -> Severity -> Risk -> Assessment), and
writes a parity snapshot of the *frozen* output. Future phases diff against it
to prove normalization does not drift consumer-visible numbers unintentionally.

Runs with SEA_CALIBRATION OFF (stable mode) unless --diagnostic is passed.

Usage:
    python -m tests.calibration_capture [--out PATH] [--show] [--diagnostic]
"""

import argparse
import json
import os
import sys

from core.evidence import EvidenceBuilder
from core.finding import Finding, ScanResult
from core.pipeline import run_engine_pipeline, run_assessment_pipeline


def _finding(module: str, evidence, occurrences: int = 1) -> Finding:
    f = Finding()
    f.module = module
    f.title = module
    f.tests_performed = 1
    f.tests_run = 1
    f.occurrences = occurrences
    f.target = "http://127.0.0.1/"
    for e in evidence:
        f.add_evidence(e)
    return f


def scenarios():
    """Returns ordered list of (name, Finding) covering each evidence pedigree."""
    eb = EvidenceBuilder()
    return [
        ("pass_verified", _finding("TLS/SSL Security", [
            eb.verified("TLS Handshake successful: TLSv1.3")])),
        ("confirmed_single", _finding("XSS Detection", [
            eb.confirmed("Reflected input confirmed", payload="<script>")])),
        ("confirmed_multi", _finding("XSS Detection", [
            eb.confirmed("Reflected input confirmed", payload="<script>"),
            eb.confirmed("Second independent reflection", payload="alert(1)")])),
        ("likely_warning", _finding("Sensitive Files", [
            eb.likely("Potential sensitive file present", payload=".env")])),
        ("possible_unknown", _finding("Open Ports", [
            eb.possible("Possible weak port", payload="8080")])),
        ("error_unknown", _finding("Source Code Leaks", [
            eb.error("Scan could not complete")])),
        ("host_reflected", _finding("Host Header Injection", [
            eb.request_response(
                "Host reflected in response",
                request={"method": "GET", "url": "http://127.0.0.1/"},
                response={"status_code": 200, "headers": {}, "body_snippet": "<a>"},
                payload="evil.com")])),
        ("sql_verified", _finding("SQL Injection", [
            eb.verified("Payload confirmed via multi-pass"),
            eb.verified("Confirmed on second method"),
            eb.verified("Cross-validated across passes")])),
    ]


def build_scan_result(items) -> ScanResult:
    from datetime import datetime
    sr = ScanResult()
    for _, f in items:
        sr.add_finding(f)
    sr.total_modules = len(sr.findings)
    sr.start_time = datetime.now()
    sr.end_time = sr.start_time
    return sr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out",
                    default="tests/fixtures/calibration/parity_baseline.json")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--diagnostic", action="store_true")
    args = ap.parse_args()

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

    sr = ScanResult()
    for _, f in items:
        sr.add_finding(f)
    sr.total_modules = len(sr.findings)
    from datetime import datetime
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

    snapshot = {
        "scheme": "v4.2-frozen",
        "generated_by": "tests/calibration_capture.py",
        "per_finding": findings_out,
        "scan": scan_out,
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2)

    if args.show:
        print(json.dumps(findings_out, indent=2))
        print("scan:", json.dumps(scan_out, indent=2))

    print(f"wrote parity snapshot -> {args.out}")

    if args.diagnostic:
        import core.feature_flags as ff
        if ff.enabled():
            ff.collector().save()

    return 0


if __name__ == "__main__":
    sys.exit(main())