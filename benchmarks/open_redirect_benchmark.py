"""
Open Redirect backbone benchmark (SOP Phase 3.6).

Self-contained offline benchmark used to measure every scanner upgrade:

  - true positives   (vulnerable fixtures detected)
  - true negatives   (clean fixtures correctly not flagged)
  - false positives  (clean flagged as vulnerable)
  - false negatives  (vulnerable missed)
  - detection rate   TP / (TP + FN)
  - average scan time

The suite stands up a local ThreadingHTTPServer that emulates several server
sides: an off-site 302 redirect, a URL-encoded off-site redirect, plus three
negative controls:

  - /internal     redirects to the SAME host (attacker string only in a query) --
                  must NOT be flagged (host-derived classification);
  - /same_origin  a relative Location on our own origin, even though the query
                  embeds an external URL -- must NOT be flagged;
  - /clean        a normal 200 page.

Usage:
    python -m benchmarks.open_redirect_benchmark
    python -m benchmarks.open_redirect_benchmark --targets https://juice.local/
"""

import os
import sys
import time
import json
import argparse
import threading
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners.open_redirect import OpenRedirectScanner
import requests


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def route(self):
        parsed = urlparse(self.path)
        qargs = parse_qs(parsed.query)
        v = next(iter(qargs.values()), [""])[0]
        return parsed.path, v

    def _host(self):
        return self.headers.get('Host', 'localhost').split(':')[0]

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header('Location', loc)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _respond(self, body):
        payload = body.encode('utf-8', 'replace')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        try:
            path, v = self.route()
        except Exception:
            path, v = "/", ""
        if path == '/external':
            return self._redirect('http://evil.com/' + v)
        if path == '/coded':
            return self._redirect('http:%2F%2Fevil.com/' + v)
        if path == '/internal':
            # same host as the request, intended only in a query arg
            return self._redirect('http://' + self._host() + '/next?u=' + v)
        if path == '/same_origin':
            return self._redirect('/welcome?from=' + v)
        return self._redirect('/')

    def do_POST(self):
        return self.do_GET()


GROUND_TRUTH = {
    '/external': True,     # off-site absolute redirect (306)
    '/coded': True,        # URL-encoded external host (encode*)
    '/internal': False,    # same-host redirect with evil in query -> NOT an open redirect
    '/same_origin': False,  # relative/own-origin Location -> NOT an open redirect
}


def _detected(target):
    sc = OpenRedirectScanner(target, session=requests.Session())
    start = time.time()
    finding = sc.scan()
    elapsed = time.time() - start
    sigs = finding.fingerprint.get('open_redirect_signals') or []
    techniques = sorted({s['technique'] for s in sigs})
    hosts = finding.fingerprint.get('redirect_targets') or []
    return bool(sigs), techniques, hosts, elapsed


def bench_local(port=None):
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    results = {}
    try:
        for endpoint, vulnerable in GROUND_TRUTH.items():
            url = f"http://127.0.0.1:{port}{endpoint}?url=http://example.com"
            detected, techniques, hosts, elapsed = _detected(url)
            results[endpoint] = {
                'vulnerable': vulnerable,
                'detected': detected,
                'techniques': techniques,
                'targets': hosts,
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
            detected, techniques, hosts, elapsed = _detected(url)
        except Exception as e:
            rows.append({'target': url, 'detected': None, 'techniques': [],
                         'scan_s': None, 'error': str(e)})
            continue
        rows.append({'target': url, 'detected': detected, 'techniques': techniques,
                     'scan_s': round(elapsed, 3)})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--targets', nargs='*', default=[])
    ap.add_argument('--out', default='reports/open_redirect_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    summary = summarize(results)
    external = run_external(args.targets) if args.targets else []

    report = {
        'scanner': 'Open Redirect detection accuracy (Phase 3.6)',
        'fixture': 'local deterministic open redirect fixture',
        'summary': summary,
        'per_endpoint': results,
        'external': external,
    }
    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print('\n=== Open Redirect benchmark (Phase 3.6) ===')
    print(f"true positives   : {summary['true_positives']}")
    print(f"false positives  : {summary['false_positives']} {summary['fp_endpoints']}")
    print(f"false negatives  : {summary['false_negatives']} {summary['fn_endpoints']}")
    print(f"true negatives   : {summary['true_negatives']}")
    print(f"detection rate   : {summary['detection_rate_pct']}%")
    print(f"average scan time: {summary['avg_scan_s']}s")
    for ep, r in results.items():
        print(f"  {ep:12s} vuln={r['vulnerable']} detected={r['detected']} "
              f"tech={r['techniques']} hosts={r['targets']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())