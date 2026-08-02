"""
Live Scan Runner — v2 vs v3 engine comparison on a REAL scan.

Runs the actual production scanners against a target (crawl + host-level +
page-level), keeps the findings RAW (no decide, no correlation), then runs both
engine paths over copies of that raw result:

  v2: tests.v2_reference.v2_decide() per finding -> run_correlation() -> get_statistics()
  v3: run_assessment_pipeline()

and emits the same Scanner Parity Report / Assessment Diff Report / verdict as
the golden regression runner. This validates the engines against genuinely
fresh scanner output — the "no scanner change without a regression safety net"
gate for Phase A8 migrations.

Usage:
  python -m tests.live_scan_runner https://example.com
  python -m tests.live_scan_runner https://example.com --max-pages 10
  python -m tests.live_scan_runner https://example.com --save-session scan.json
  python -m tests.live_scan_runner --session scan.json   # re-run engines on saved raw findings

Exit code 1 when the scan REGRESSES (any unexplained v2/v3 difference).
"""

import argparse
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

from core.evidence import Evidence, EvidenceLevel, EvidenceType
from core.finding import Finding, ScanResult, Status, Severity
from tests.diffing import classify_scenario, diff_assessment, diff_findings
from tests.engine_paths import run_v2_on, run_v3_on
from tests.regression_runner import assessment_diff_report, scanner_parity_table


# ===== raw scan =============================================================

def _host(target: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(target)
    return f"{parsed.scheme}://{parsed.netloc}"


def live_scan(target: str, max_pages: int = 5, timeout: int = 10) -> ScanResult:
    """Run the real scanners against a target; findings stay provisional (raw).

    Mirrors the production orchestration (crawl -> host scan -> page scan ->
    aggregate safe findings) but never runs the assessment pipeline / correlation,
    so the same raw input can be pushed through both the v2 and v3 engine paths.
    """
    from core.config import ScanConfig
    from core.crawler import Crawler
    from core.http_client import TrackedSession
    from scanners.registry import ALL_SCANNERS, HOST_LEVEL_SCANNERS, PAGE_LEVEL_SCANNERS

    cfg = ScanConfig()
    cfg.max_pages = max_pages
    cfg.request_timeout = timeout
    cfg.long_request_timeout = min(int(timeout * 1.5), 30)

    session = TrackedSession()
    session.headers.update({"User-Agent": cfg.user_agent})

    scan_result = ScanResult()
    scan_result.total_modules = len(ALL_SCANNERS)

    crawler = Crawler(session=session, use_js=False)
    pages = crawler.crawl(target, max_pages=max_pages, js_wait_seconds=0)
    pages = [p for p in pages if p.get("params") or p.get("forms") or p.get("js_variables")]
    if not pages:
        pages = [{"url": target, "params": {}, "forms": []}]

    scan_result.pages_crawled = len(pages)
    scan_result.urls_discovered = list(crawler.visited) if hasattr(crawler, "visited") else []

    host = _host(target)
    for scanner_class in HOST_LEVEL_SCANNERS:
        try:
            # scan() = raw evidence collection only. run() applies engines;
            # the harness applies both engine paths itself (run_v2_on/run_v3_on).
            finding = scanner_class(host, session=session).scan()
            scan_result.add_finding(finding)
        except Exception as exc:
            _error_finding(scan_result, scanner_class.__name__, str(exc))

    for page in pages:
        page_url = page["url"]
        params = page.get("params", {})
        forms = page.get("forms", [])
        if params:
            from urllib.parse import urlencode
            qs = urlencode(params, doseq=True)
            page_url = page_url + ("&" if "?" in page_url else "?") + qs
        post_data = forms[0]["fields"] if forms and forms[0].get("fields") else None
        for scanner_class in PAGE_LEVEL_SCANNERS:
            try:
                finding = scanner_class(page_url, session=session, post_data=post_data).scan()
                scan_result.add_finding(finding)
            except Exception as exc:
                _error_finding(scan_result, scanner_class.__name__, str(exc))

    scan_result.requests_sent = getattr(session, "request_count", 0)
    scan_result.aggregate_safe_findings()
    return scan_result


def _error_finding(scan_result: ScanResult, module: str, message: str) -> None:
    from core.evidence import EvidenceBuilder
    f = Finding()
    f.module = module
    f.module_name = module
    f.title = f"{module} scan failed"
    f.description = f"Scanner raised an exception: {message}"
    f.status = Status.UNKNOWN
    f.severity = Severity.NONE
    f.confidence = 0
    f.add_evidence(EvidenceBuilder.error(message))
    scan_result.add_finding(f)


# ===== session persistence (raw findings only) =============================

_SERIALIZABLE_META = [
    "total_modules", "requests_sent", "injection_payloads", "headers_tests",
    "port_tests", "pages_crawled", "urls_crawled", "urls_skipped",
    "useful_pages", "not_useful_pages", "js_discovered_urls", "forms_discovered",
    "hidden_inputs", "params_discovered", "cookies_found", "auth_detected",
    "auth_confidence", "auth_method", "auth_state", "auth_state_label",
    "auth_accessible", "auth_blocked", "auth_redirected", "auth_unauthorized",
    "auth_unknown", "auth_public_pages", "auth_authenticated_pages",
    "auth_coverage_public", "auth_coverage_authenticated", "auth_coverage_overall",
    "auth_coverage_improvement", "auth_est_improvement",
]


def session_to_dict(sr: ScanResult, target: str = "") -> dict:
    return {
        "target": target,
        "meta": {k: getattr(sr, k, None) for k in _SERIALIZABLE_META},
        "lists": {
            "urls_discovered": sr.urls_discovered,
            "api_endpoints": sr.api_endpoints,
            "directories_discovered": sr.directories_discovered,
            "interesting_files": sr.interesting_files,
            "js_files": sr.js_files,
            "technologies": sr.technologies,
            "authentication_pages": sr.authentication_pages,
            "admin_pages": sr.admin_pages,
            "auth_reasons": sr.auth_reasons,
            "auth_protected_areas": sr.auth_protected_areas,
            "skip_reasons": sr.skip_reasons,
        },
        "headers_found": sr.headers_found,
        "crawler_type": sr.crawler_type,
        "findings": [f.to_dict() for f in sr.findings],
    }


def session_from_dict(data: dict) -> ScanResult:
    sr = ScanResult()
    meta = data.get("meta", {})
    for key, value in meta.items():
        if hasattr(sr, key):
            setattr(sr, key, value)
    for key, value in data.get("lists", {}).items():
        if hasattr(sr, key):
            setattr(sr, key, copy.deepcopy(value))
    if "headers_found" in data:
        sr.headers_found = dict(data.get("headers_found") or {})
    if "crawler_type" in data:
        sr.crawler_type = data.get("crawler_type", "http")
    for fd in data.get("findings", []):
        sr.add_finding(_rehydrate_finding(fd))
    return sr


def _rehydrate_finding(d: dict) -> Finding:
    f = Finding()
    for key, value in d.items():
        if key in ("status", "severity", "exploitability", "execution_state", "evidence"):
            continue
        if key in f.__dict__:
            setattr(f, key, copy.deepcopy(value))
    f.status = _enum(Status, d.get("status", "unknown"))
    f.severity = _enum(Severity, d.get("severity", "none"))
    for ev in d.get("evidence", []):
        f.evidence.append(_rehydrate_evidence(ev))
    return f


def _rehydrate_evidence(d: dict) -> Evidence:
    return Evidence(
        level=_enum(EvidenceLevel, d.get("level", "unknown")),
        type=_enum(EvidenceType, d.get("type", "configuration")),
        description=d.get("description", ""),
        payload=d.get("payload"),
        endpoint=d.get("endpoint"),
        parameter=d.get("parameter"),
        method=d.get("method", "GET"),
        timestamp=d.get("timestamp", ""),
        raw_data=dict(d.get("raw_data") or {}),
        confidence_bonus=int(d.get("confidence_bonus", 0)),
        weight=int(d.get("weight", 1)),
        verification_pass=int(d.get("verification_pass", 0)),
        verification_method=d.get("verification_method", ""),
    )


def _enum(enum_cls, value):
    try:
        return enum_cls(value)
    except Exception:
        return None


# ===== report ==============================================================

def _scenario_lines(target: str, v2: dict, v3: dict) -> dict:
    finding_diffs = diff_findings(v2, v3)
    assessment_diffs = diff_assessment(v2, v3, finding_diffs)
    verdict = classify_scenario(finding_diffs, assessment_diffs)

    lines = [f"\nLive target: {target}"]
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
                f"v2={d['v2']} -> v3={d['v3']} ({d['category']})"
            )
            lines.append(f"         {d['reason']}")
    else:
        lines.append("  Differences: none — exact engine parity.")

    lines.append(f"  VERDICT: {verdict}")
    return {'verdict': verdict, 'lines': lines,
            'finding_diffs': finding_diffs, 'assessment_diffs': assessment_diffs}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='live v2 vs v3 engine comparison')
    parser.add_argument('target', nargs='?', help='URL to scan')
    parser.add_argument('--session', help='re-run engines on a saved raw session JSON')
    parser.add_argument('--save-session', help='save the raw scan session to a JSON file')
    parser.add_argument('--max-pages', type=int, default=5)
    parser.add_argument('--timeout', type=int, default=10)
    args = parser.parse_args(argv)

    if not args.target and not args.session:
        parser.error("provide a target URL or --session FILE")

    if args.session:
        with open(args.session, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        raw = session_from_dict(data)
        target = data.get('target', args.session)
        print(f"[source: session {args.session}]")
    else:
        print(f"[scanning] {args.target}")
        raw = live_scan(args.target, max_pages=args.max_pages, timeout=args.timeout)
        target = args.target
        print(f"[scan complete] {len(raw.findings)} finding(s)")
        if args.save_session:
            with open(args.save_session, 'w', encoding='utf-8') as fh:
                json.dump(session_to_dict(raw, target=target), fh, indent=2, default=str)
            print(f"[session saved] {args.save_session}")

    v2 = run_v2_on(session_from_dict(session_to_dict(raw, target=target)))
    v3 = run_v3_on(session_from_dict(session_to_dict(raw, target=target)))

    res = _scenario_lines(target, v2, v3)
    for line in res['lines']:
        print(line)

    verdict = res['verdict']
    print(f"\nRESULT: {verdict}")
    return 1 if verdict == 'REGRESSION' else 0


if __name__ == '__main__':
    sys.exit(main())
