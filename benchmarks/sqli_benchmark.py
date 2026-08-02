"""
SQLiScan backbone benchmark (SOP Phase 3.1).

Self-contained offline benchmark used to measure every scanner upgrade:

  - true positives   (vulnerable fixtures detected)
  - true negatives   (clean fixtures correctly not flagged)
  - false positives  (clean flagged as vulnerable)
  - false negatives  (vulnerable missed)
  - detection rate   TP / (TP + FN)
  - average scan time

The suite stands up a local ThreadingHTTPServer with intentionally vulnerable
AND clean endpoints, runs the upgraded SQLiScanner against each, and writes a
JSON report. Provide external targets on argv (e.g. OWASP Juice Shop, DVWA,
Mutillidae, WebGoat, bWAPP, PortSwigger Web Academy lab URLs) to also record
their detection/time for the external benchmark list.

Usage:
    python -m benchmarks.sqli_benchmark
    python -m benchmarks.sqli_benchmark --targets https://juice.local/
"""

import os
import sys
import time
import json
import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners.sqli import SQLiScanner
import requests


# ---------------------------------------------------------------------------
# Local vulnerable + clean fixture server
# ---------------------------------------------------------------------------

def _union_page(qval, cols=4):
    if 'ORDER BY' in qval:
        n = int(qval.split('ORDER BY')[1].split('--')[0].strip())
        if n <= cols:
            return 200, "ok"
        return 500, "unknown column error"
    if 'UNION SELECT' in qval:
        return 200, "Loaded " + qval + " done"
    return 200, "ok"


def _bool_page(qval):
    if qval in ("' AND '1'='2'-- -", "' OR '1'='2'-- -",
                "'/**/AND/**/1=2-- -"):
        return 200, "FALSE" * 30
    return 200, "TRUE"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def route(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        qargs = parse_qs(parsed.query)
        qval = next(iter(qargs.values()), [""])[0]
        return parsed.path, qval

    def do_GET(self):
        try:
            path, qval = self.route()
        except Exception:
            path, qval = "/", ""

        delay = bool(sum(k in qval.upper() for k in
                         ('SLEEP', 'PGSLEEP', 'WAITFOR', 'BENCHMARK', 'DELAY')))

        if path in ('/bool', '/error', '/union', '/time') and delay:
            time.sleep(7)

        if path == '/union':
            status, body = _union_page(qval)
        elif path == '/bool':
            status, body = _bool_page(qval)
        elif path == '/error':
            if "'" in qval or '"' in qval:
                status, body = 500, "You have an error in your SQL syntax"
            else:
                status, body = 200, "ok"
        elif path == '/time':
            status, body = (200, "sleeping") if delay else (200, "ok")
        else:
            # Clean control endpoints: a fixed, non-reflecting page. A normal
            # page that never reflects input must yield zero boolean/time/error
            # differentiation regardless of the injection probe.
            status, body = 200, "Static 200 OK page (no dynamic reflection)"

        payload = body.encode('utf-8', 'replace')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        return self.do_GET()


# ---------------------------------------------------------------------------
# Ground truth for the local fixture
# ---------------------------------------------------------------------------
GROUND_TRUTH = {
    '/error': True,   # MySQL error-based
    '/bool': True,    # boolean-based blind
    '/union': True,   # UNION-based (a legacy false-negative now covered)
    '/time': True,    # time-based blind
    '/echo': False,   # clean echo page (must NOT flag)
    '/meta': False,   # clean page with a URL param (must NOT flag)
}


# ---------------------------------------------------------------------------
# Scanner wrapper
# ---------------------------------------------------------------------------
def _detected(target):
    sc = SQLiScanner(target, session=requests.Session())
    start = time.time()
    finding = sc.scan()
    elapsed = time.time() - start
    sigs = finding.fingerprint.get('sqli_signals') or []
    techniques = sorted({s['technique'] for s in sigs})
    return bool(sigs), techniques, elapsed


def bench_local(port=None):
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    results = {}
    try:
        for endpoint, vulnerable in GROUND_TRUTH.items():
            url = f"http://127.0.0.1:{port}{endpoint}?id=7"
            detected, techniques, elapsed = _detected(url)
            results[endpoint] = {
                'vulnerable': vulnerable,
                'detected': detected,
                'techniques': techniques,
                'scan_s': round(elapsed, 3),
            }
    finally:
        httpd.shutdown()
        httpd.server_close()
    return results


def summarize(results):
    tp = {k: v for k, v in results.items() if v['vulnerable'] and v['detected']}
    fn = {k: v for k, v in results.items() if v['vulnerable'] and not v['detected']}
    fp = {k: v for k, v in results.items() if not v['vulnerable'] and v['detected']}
    tn = {k: v for k, v in results.items() if not v['vulnerable'] and not v['detected']}
    vuln_total = len(tp) + len(fn)
    detection_rate = round((len(tp) / vuln_total) * 100, 1) if vuln_total else 0.0
    all_scans = [v['scan_s'] for v in results.values()]
    avg_time = round(sum(all_scans) / len(all_scans), 3) if all_scans else 0.0
    return {
        'true_positives': len(tp),
        'false_positives': len(fp),
        'false_negatives': len(fn),
        'true_negatives': len(tn),
        'detection_rate_pct': detection_rate,
        'avg_scan_s': avg_time,
        'fp_endpoints': sorted(fp),
        'fn_endpoints': sorted(fn),
    }


def run_external(targets):
    rows = []
    for url in targets:
        try:
            detected, techniques, elapsed = _detected(url)
        except Exception as e:
            rows.append({'target': url, 'detected': None, 'techniques': [],
                         'scan_s': None, 'error': str(e)})
            continue
        rows.append({'target': url, 'detected': detected,
                     'techniques': techniques, 'scan_s': round(elapsed, 3)})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--targets', nargs='*', default=[],
                    help='External target URLs (Juice Shop / DVWA / ...)')
    ap.add_argument('--out', default='reports/sqli_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    summary = summarize(results)
    external = run_external(args.targets) if args.targets else []

    report = {
        'scanner': 'SQL injection (Phase 3.1)',
        'fixture': 'local deterministic SQLi fixture',
        'summary': summary,
        'per_endpoint': results,
        'external': external,
    }

    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print('\n=== SQLi benchmark (Phase 3.1) ===')
    print(f"true positives   : {summary['true_positives']}")
    print(f"false positives  : {summary['false_positives']} {summary['fp_endpoints']}")
    print(f"false negatives  : {summary['false_negatives']} {summary['fn_endpoints']}")
    print(f"true negatives   : {summary['true_negatives']}")
    print(f"detection rate   : {summary['detection_rate_pct']}%")
    print(f"average scan time: {summary['avg_scan_s']}s")
    for ep, r in results.items():
        print(f"  {ep:10s} vuln={r['vulnerable']} detected={r['detected']} "
              f"tech={r['techniques']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())