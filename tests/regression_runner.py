"""
Golden Regression Runner — v2 vs v3 engine comparison for every corpus scenario.

Outputs:
  1. Scanner Parity Report  — per module: old (v2) vs new (v3) vs expected, result.
  2. Assessment Diff Report — risk score / overall / coverage differences, each
                              with an explanation.
  3. Verdict per scenario    — PASS | WARNING (only explained diffs) | REGRESSION.

Usage:
  python -m tests.regression_runner            # run all scenarios
  python -m tests.regression_runner --name sqli_detected
  python -m tests.regression_runner --write-golden   # persist v2 baselines

Exit code 0 when no scenario REGRESSES.
"""

import argparse
import json
import os
import sys
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

from tests.corpus import build_scenario, scenario_description, scenario_names
from tests.diffing import classify_scenario, diff_assessment, diff_findings, normalize_verification
from tests.engine_paths import run_v2, run_v3

GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures', 'golden')

STATUS_COLOR = {'PASS': 'PASS', 'WARNING': 'WARNING', 'REGRESSION': 'REGRESSION'}


def _fmt(v) -> str:
    return str(v)


def scanner_parity_table(v2: Dict, v3: Dict, diffs: List[Dict]) -> List[str]:
    rows = []
    header = (
        f"{'Module':<26} {'Status':<9} {'v2 Se':<8} {'v3 Se':<8} "
        f"{'v2 Co':<6} {'v3 Co':<6} {'v2 Ve':<12} {'v3 Ve':<12} Result"
    )
    rows.append(header)
    rows.append('-' * len(header))
    v2_by = {f['module']: f for f in v2['findings']}
    v3_by = {f['module']: f for f in v3['findings']}
    diff_map = {(d['module'], d['field']): d for d in diffs}
    for module in sorted(set(v2_by) | set(v3_by)):
        f2 = v2_by.get(module)
        f3 = v3_by.get(module)
        if f2 is None or f3 is None:
            rows.append(f"{module:<26} {'-':<9} {'-':<8} {'-':<8} {'-':<6} "
                        f"{'-':<6} {'-':<12} {'-':<12} REGRESSION")
            continue
        sev_diff = diff_map.get((module, 'severity'))
        conf_diff = diff_map.get((module, 'confidence'))
        ver_diff = diff_map.get((module, 'verification'))
        has_regression = any(
            d for d in (sev_diff, conf_diff)
            if d is not None and not d['explained']
        )
        result = 'REGRESSION' if has_regression else 'OK'
        rows.append(
            f"{module:<26} {f3['status']:<9} {f2['severity']:<8} {f3['severity']:<8} "
            f"{f2['confidence']:<6} {f3['confidence']:<6} "
            f"{f2['verification']:<12} {f3['verification']:<12} {result}"
        )
    return rows


def assessment_diff_report(v2: Dict, v3: Dict, diffs: List[Dict]) -> List[str]:
    rows = []
    rows.append("Risk score       : "
                f"v2 {_fmt(v2['risk_score'])}  v3 {_fmt(v3['risk_score'])}  "
                f"diff {v3['risk_score'] - v2['risk_score']:+.1f}")
    rows.append("Risk grade       : "
                f"v2 {_fmt(v2['risk_grade'])}  v3 {_fmt(v3['risk_grade'])}")
    rows.append("Overall tier     : "
                f"v2 {_fmt(v2['overall']['tier'])}  v3 {_fmt(v3['overall']['tier'])}")
    rows.append("Overall label    : "
                f"v2 {_fmt(v2['overall']['label'])}  v3 {_fmt(v3['overall']['label'])}")
    rows.append("Coverage         : "
                f"v2 {v2['coverage']['executed']}/{v2['coverage']['total']} "
                f"({v2['coverage']['percent']}%)  "
                f"v3 {v3['coverage']['executed']}/{v3['coverage']['total']} "
                f"({v3['coverage']['percent']}%)")
    rows.append(f"Verified vulns   : v2 {v2['verified_vulns']}  v3 {v3['verified_vulns']}")
    rows.append(f"Likely vulns     : v2 {v2['likely_vulns']}  v3 {v3['likely_vulns']}")
    rows.append(f"Correlations     : v2 {v2['correlations_found']}  v3 {v3['correlations_found']}")
    return rows


def run_scenario(name: str, golden: Dict = None) -> Dict:
    v2 = golden if golden is not None else run_v2(name)
    v3 = run_v3(name)

    finding_diffs = diff_findings(v2, v3)
    assessment_diffs = diff_assessment(v2, v3, finding_diffs)
    verdict = classify_scenario(finding_diffs, assessment_diffs)

    lines = [f"\nScenario: {name} — {scenario_description(name)}"]
    lines.append("  ---- Scanner Parity Report ----")
    for row in scanner_parity_table(v2, v3, finding_diffs):
        lines.append("  " + row)
    lines.append("  ---- Assessment Diff Report ----")
    for row in assessment_diff_report(v2, v3, assessment_diffs):
        lines.append("  " + row)

    all_diffs = finding_diffs + assessment_diffs
    if all_diffs:
        lines.append("  ---- Differences (every diff explained) ----")
        for d in all_diffs:
            tag = 'EXPLAINED' if d['explained'] else 'REGRESSION'
            lines.append(
                f"  [{tag}] {d['module']}.{d['field']}: "
                f"v2={_fmt(d['v2'])} -> v3={_fmt(d['v3'])} "
                f"({d['category']})"
            )
            lines.append(f"         {d['reason']}")
    else:
        lines.append("  Differences: none — exact engine parity.")

    lines.append(f"  VERDICT: {verdict}")
    return {'name': name, 'verdict': verdict, 'lines': lines,
            'finding_diffs': finding_diffs, 'assessment_diffs': assessment_diffs}


def write_golden() -> None:
    os.makedirs(GOLDEN_DIR, exist_ok=True)
    for name in scenario_names():
        v2 = run_v2(name)
        with open(os.path.join(GOLDEN_DIR, f'{name}.json'), 'w', encoding='utf-8') as fh:
            json.dump(v2, fh, indent=2, default=str)
    print(f"Golden baselines written to {GOLDEN_DIR}")


def load_golden(name: str) -> Dict:
    path = os.path.join(GOLDEN_DIR, f'{name}.json')
    if not os.path.exists(path):
        return None
    with open(path, 'r', encoding='utf-8') as fh:
        return json.load(fh)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='v2 vs v3 golden regression runner')
    parser.add_argument('--name', help='run a single scenario by name')
    parser.add_argument('--write-golden', action='store_true',
                        help='persist v2 baselines under tests/fixtures/golden')
    args = parser.parse_args(argv)

    if args.write_golden:
        write_golden()
        return 0

    names = [args.name] if args.name else scenario_names()
    results: List[Dict] = []
    for name in names:
        golden = load_golden(name)
        source = 'golden' if golden is not None else 'live v2'
        res = run_scenario(name, golden=golden)
        print(f"[baseline: {source}]")
        for line in res['lines']:
            print(line)
        results.append(res)

    print("\n===== SUMMARY =====")
    counts = {'PASS': 0, 'WARNING': 0, 'REGRESSION': 0}
    for r in results:
        counts[r['verdict']] += 1
        print(f"  {r['verdict']:<10} {r['name']}")
    print(f"\nPASS={counts['PASS']}  WARNING={counts['WARNING']}  "
          f"REGRESSION={counts['REGRESSION']}")
    return 1 if counts['REGRESSION'] else 0


if __name__ == '__main__':
    sys.exit(main())
