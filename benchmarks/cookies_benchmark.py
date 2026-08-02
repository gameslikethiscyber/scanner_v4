"""
Cookies security benchmark (Phase 3.9).

Local deterministic fixture serving various Set-Cookie policies. Measures the
Cookies v4.8.0 upgrade Before vs After (Secure / HttpOnly / SameSite / prefix /
persistence / domain-scope / session identification / insecure combos):

Fixtures (truth):
  /unsecure_session        session cookie missing Secure                vuln
  /no_httponly_session     session cookie not HttpOnly                 vuln
  /prefix_misuse           __Host- cookie without Secure               vuln
  /persistent_session      long-lived session cookie (1y Max-Age)      vuln
  /broad_domain            Domain=com (TLD-wide scope)                 vuln
  /good_session            fully hardened session cookie               clean
  /asset_nosession         ordinary non-session cookie, minimal flags  clean
  /clean_batch             several hardened cookies                    clean

Usage:
    python -m benchmarks.cookies_benchmark
"""

import os
import sys
import time
import json
import argparse
import threading
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners.cookies import CookiesScanner
import requests

FIXTURES = {
    '/unsecure_session': ['sid=abc123; HttpOnly; SameSite=Lax; Path=/'],
    '/no_httponly_session': ['sid=abc123; Secure; SameSite=Lax; Path=/'],
    '/prefix_misuse': ['__Host-sid=abc123; HttpOnly; Path=/'],
    '/persistent_session': [
        'sid=abc123; Secure; HttpOnly; SameSite=Lax; Max-Age=31536000; Path=/'],
    '/broad_domain': ['sid=abc123; Secure; HttpOnly; SameSite=Lax; Domain=com; Path=/'],
    '/good_session': ['sid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/'],
    '/asset_nosession': ['visitor=987654; Path=/'],
    '/clean_batch': [
        'sid=abc123; Secure; HttpOnly; SameSite=Lax; Path=/',
        'pref=dark; Secure; HttpOnly; SameSite=Lax; Path=/',
    ],
}

GROUND_TRUTH = {
    '/unsecure_session': True,
    '/no_httponly_session': True,
    '/prefix_misuse': True,
    '/persistent_session': True,
    '/broad_domain': True,
    '/good_session': False,
    '/asset_nosession': False,
    '/clean_batch': False,
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _respond(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        for sc in FIXTURES.get(urlparse(self.path).path, []):
            self.send_header('Set-Cookie', sc)
        self.send_header('Content-Length', '5')
        self.end_headers()
        self.wfile.write(b'index')

    def do_GET(self):
        self._respond()

    def do_HEAD(self):
        self._respond()


def _detected(target):
    sc = CookiesScanner(target, session=requests.Session())
    start = time.time()
    finding = sc.scan()
    elapsed = time.time() - start
    sigs = finding.fingerprint.get('cookie_issues') or []
    issue_types = sorted({i['type'] for i in sigs})
    return bool(sigs), issue_types, elapsed


def bench_local():
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    results = {}
    try:
        for endpoint, vulnerable in GROUND_TRUTH.items():
            url = f"http://127.0.0.1:{port}{endpoint}"
            detected, issue_types, elapsed = _detected(url)
            results[endpoint] = {
                'vulnerable': vulnerable,
                'detected': detected,
                'issues': issue_types,
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
    vtotal = len(tp) + len(fn)
    dr = round((len(tp) / vtotal) * 100, 1) if vtotal else 0.0
    all_scans = [v['scan_s'] for v in results.values()]
    avg = round(sum(all_scans) / len(all_scans), 3) if all_scans else 0.0
    return {'true_positives': len(tp), 'false_positives': len(fp),
            'false_negatives': len(fn), 'true_negatives': len(tn),
            'detection_rate_pct': dr, 'avg_scan_s': avg,
            'fp_endpoints': sorted(fp), 'fn_endpoints': sorted(fn)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--targets', nargs='*', default=[])
    ap.add_argument('--out', default='reports/cookies_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    summary = summarize(results)
    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump({'scanner': 'Cookies security (Phase 3.9)',
                   'fixture': 'local deterministic cookies fixture',
                   'summary': summary, 'per_endpoint': results}, f, indent=2)

    print('\n=== Cookies benchmark (Phase 3.9) ===')
    print(f"true positives   : {summary['true_positives']}")
    print(f"false positives  : {summary['false_positives']} {summary['fp_endpoints']}")
    print(f"false negatives  : {summary['false_negatives']} {summary['fn_endpoints']}")
    print(f"true negatives   : {summary['true_negatives']}")
    print(f"detection rate   : {summary['detection_rate_pct']}%")
    print(f"average scan time: {summary['avg_scan_s']}s")
    for ep, r in results.items():
        print(f"  {ep:20s} vuln={r['vulnerable']} detected={r['detected']} "
              f"issues={r['issues']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())