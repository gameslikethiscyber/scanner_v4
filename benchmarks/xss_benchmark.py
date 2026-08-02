"""
XSS backbone benchmark (SOP Phase 3.2).

Self-contained offline benchmark used to measure every scanner upgrade:

  - true positives   (vulnerable fixtures detected)
  - true negatives   (clean fixtures correctly not flagged)
  - false positives  (clean flagged as vulnerable)
  - false negatives  (vulnerable missed)
  - detection rate   TP / (TP + FN)
  - average scan time

The suite stands up a local ThreadingHTTPServer with intentionally vulnerable
AND clean endpoints, runs the upgraded XSSScanner against each, and writes a
JSON report. Provide external targets on argv (e.g. OWASP Juice Shop, DVWA,
bWAPP, PortSwigger Web Academy XSS labs) to also record their detection/time.

Usage:
    python -m benchmarks.xss_benchmark
    python -m benchmarks.xss_benchmark --targets https://juice.local/
"""

import os
import sys
import time
import json
import argparse
import threading
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners.xss import XSSScanner
import requests


# ---------------------------------------------------------------------------
# Local vulnerable + clean fixture server
# ---------------------------------------------------------------------------

def _reflect(body_tpl, qval):
    return body_tpl + qval + body_tpl[::-1]


def _html_page(qval):
    if '<script>' in qval or '<img ' in qval or '<svg ' in qval:
        return f"<p>hi</p>{qval}<p>done</p>"
    return _reflect("<p>page ", qval)


def _attr_page(qval):
    # Raw reflection inside a double-quoted href -> breakable attribute.
    return f'<a href="{qval}">link</a>' + qval


def _dom_page(qval):
    # Reflected value flows into a DOM sink inside an inline <script>.
    return ("<script>var p='" + qval +
            "';document.getElementById('out').innerHTML=p;</script>")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def route(self):
        parsed = urlparse(self.path)
        qargs = parse_qs(parsed.query)
        qval = next(iter(qargs.values()), [""])[0]
        return parsed.path, qval

    def do_GET(self):
        try:
            path, qval = self.route()
        except Exception:
            path, qval = "/", ""

        if path == '/html':
            body = _html_page(qval)
        elif path == '/attr':
            body = _attr_page(qval)
        elif path == '/dom':
            body = _dom_page(qval)
        elif path == '/clean':
            # No reflection at all: input is dropped from the response.
            body = "<p>static page, no reflected input</p>"
        elif path == '/escaped':
            # Server entity-escapes the input before reflection (output encoding).
            import html as _html
            body = "<p>hello " + _html.escape(qval) + "</p>"
        else:
            body = "Static 200 OK page"

        payload = body.encode('utf-8', 'replace')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        return self.do_GET()


GROUND_TRUTH = {
    '/html': True,    # reflected into raw HTML -> script tag
    '/attr': True,    # reflected into a double-quoted attribute
    '/dom': True,     # reflected value reaches a DOM sink (indicative)
    '/clean': False,  # static page, no reflection
    '/escaped': False,  # escaped output must NOT be flagged
}


def _detected(target):
    sc = XSSScanner(target, session=requests.Session())
    start = time.time()
    finding = sc.scan()
    elapsed = time.time() - start
    sigs = finding.fingerprint.get('xss_signals') or []
    contexts = sorted({s['context'] for s in sigs})
    support = finding.fingerprint.get('support_signals') or []
    return bool(sigs), contexts, support, elapsed


def bench_local(port=None):
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    results = {}
    try:
        for endpoint, vulnerable in GROUND_TRUTH.items():
            url = f"http://127.0.0.1:{port}{endpoint}?q=probe"
            detected, contexts, support, elapsed = _detected(url)
            results[endpoint] = {
                'vulnerable': vulnerable,
                'detected': detected,
                'contexts': contexts,
                'support': support,
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
            detected, contexts, support, elapsed = _detected(url)
        except Exception as e:
            rows.append({'target': url, 'detected': None, 'contexts': [],
                         'scan_s': None, 'error': str(e)})
            continue
        rows.append({'target': url, 'detected': detected,
                     'contexts': contexts, 'scan_s': round(elapsed, 3)})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--targets', nargs='*', default=[],
                    help='External target URLs')
    ap.add_argument('--out', default='reports/xss_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    summary = summarize(results)
    external = run_external(args.targets) if args.targets else []

    report = {
        'scanner': 'XSS detection (Phase 3.2)',
        'fixture': 'local deterministic XSS fixture',
        'summary': summary,
        'per_endpoint': results,
        'external': external,
    }

    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print('\n=== XSS benchmark (Phase 3.2) ===')
    print(f"true positives   : {summary['true_positives']}")
    print(f"false positives  : {summary['false_positives']} {summary['fp_endpoints']}")
    print(f"false negatives  : {summary['false_negatives']} {summary['fn_endpoints']}")
    print(f"true negatives   : {summary['true_negatives']}")
    print(f"detection rate   : {summary['detection_rate_pct']}%")
    print(f"average scan time: {summary['avg_scan_s']}s")
    for ep, r in results.items():
        print(f"  {ep:10s} vuln={r['vulnerable']} detected={r['detected']} "
              f"ctx={r['contexts']} support={r['support']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())