"""Generate deterministic sample security reports for presentation work.

Builds several canonical scans from the golden corpus, runs the full assessment
pipeline (no scanner/engine modification), and renders an HTML report for each.
Used to produce before/after artifacts and screenshots for the professional
HTML report redesign. Engine and assessment output are untouched — this is a
presentation-only harness.

Usage:
    python tools/report_sample.py --out <dir> [--scenarios mixed_corpus,..]
"""

import argparse
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline import run_assessment_pipeline
from core.reporter import Reporter
from tests.corpus import build_scenario, scenario_names

DEFAULT_TARGET = "https://corp-app.example.com"


def build(scan_result, target=DEFAULT_TARGET):
    """Run the assessment pipeline on a scenario, return the assessed ScanResult."""
    scan_result.total_modules = scan_result.total_modules or len(scan_result.findings)
    scan_result.start_time = datetime.now()
    scan_result.end_time = scan_result.start_time
    run_assessment_pipeline(scan_result)
    return scan_result


def render(scan_result, out_dir, name, target=DEFAULT_TARGET):
    """Render an HTML report to out_dir/<name>.html using the live Reporter.

    Uses the production ``Reporter.generate_html`` path (same filtering and
    validation the real CLI uses) so sample reports match deployed output
    exactly, then renames the timestamped file to the scenario name.
    """
    os.makedirs(out_dir, exist_ok=True)
    reporter = Reporter(
        branding={
            "company_name": "SEA Corporate",
            "client_name": "Acme Industries",
            "consultant_name": "Lead Security Consultant",
            "report_id": "SEA-2026-0812",
        }
    )
    reporter.report_dir = out_dir
    path = reporter.generate_html(scan_result, target)
    if not path:
        raise SystemExit(f"[ERROR] generate_html failed for {name}")
    renamed = os.path.join(out_dir, f"{name}.html")
    os.replace(path, renamed)
    return renamed


def main():
    ap = argparse.ArgumentParser(description="Generate sample HTML reports")
    ap.add_argument("--out", default="reports/samples")
    ap.add_argument("--scenarios", default="mixed_corpus,clean_site")
    args = ap.parse_args()

    names = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    for name in names:
        if name not in scenario_names():
            print(f"[skip] unknown scenario: {name}")
            continue
        sr = build(build_scenario(name))
        path = render(sr, args.out, name)
        print(f"[OK] {name} -> {path}")


if __name__ == "__main__":
    main()
