"""
CORS backbone benchmark (Phase 3.8).

Self-contained local HTTPS fixture that emulates several server-side CORS
policies, used to measure the CORS v4.7.0 accuracy upgrade Before vs After:

  * origin reflection / credentials / wildcard / null / multiple-origin
  * cross-method confirmation (a policy that only reflects on POST)
  * preflight (OPTIONS) analysis

Fixtures:
  /reflected       reflects any Origin (no credentials)                 vuln
  /reflected_creds reflects Origin + Allow-Credentials: true          vuln
  /wildcard_creds  returns '*' with Allow-Credentials: true           vuln
  /null            reflects 'null' origin                              vuln
  /post_only        only reflects Origin on POST (GET is restrictive)  vuln
  /allowlist       allows only a fixed trusted domain (no reflection)  clean
  /no_acao         no CORS headers                                     clean

Usage:
    python -m benchmarks.cors_benchmark
    python -m benchmarks.cors_benchmark --targets https://api.example.com/
"""

import os
import sys
import time
import json
import argparse
import threading
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners.cors import CORSScanner
import requests

TRUSTED = 'https://trusted.example.com'


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, extra_headers):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', '2')
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b'{}')

    def _do(self, method):
        path = urlparse(self.path).path
        origin = self.headers.get('Origin', '')
        if method == 'OPTIONS':
            req_method = self.headers.get('Access-Control-Request-Method', 'GET')
            acao = _acao(path.strip('/'), origin, req_method)
            if acao is None:
                return self._send(200, {})
            mm = '*' if path.strip('/') == 'wildcard_creds' else req_method
            h = {'Access-Control-Allow-Origin': acao,
                 'Access-Control-Allow-Methods': mm or req_method,
                 'Access-Control-Allow-Headers': 'Content-Type'}
            if path.strip('/') in ('reflected_creds', 'wildcard_creds'):
                h['Access-Control-Allow-Credentials'] = 'true'
            return self._send(200, h)
        acao = _acao(path.strip('/'), origin, method)
        if acao is None:
            return self._send(200, {})
        h = {'Access-Control-Allow-Origin': acao}
        if acao != '*' and path.strip('/') in ('reflected_creds',):
            h['Access-Control-Allow-Credentials'] = 'true'
        if acao != '*' and path.strip('/') == 'wildcard_creds':
            h['Access-Control-Allow-Credentials'] = 'true'
        return self._send(200, h)

    def do_GET(self):
        return self._do('GET')

    def do_POST(self):
        return self._do('POST')

    def do_OPTIONS(self):
        return self._do('OPTIONS')


def _acao(mode, origin, method):
    if mode == 'allowlist':
        return TRUSTED if origin == TRUSTED else None
    if mode == 'no_acao':
        return None
    if mode == 'wildcard_creds':
        return '*'
    if mode == 'reflected_creds':
        return origin or None
    if mode == 'reflected':
        return origin if origin in ('https://evil.com', 'https://attacker.com') else None
    if mode == 'null':
        return origin if origin == 'null' else None
    if mode == 'post_only':
        return origin if (method == 'POST' and
                          origin in ('https://evil.com', 'https://attacker.com')) else None
    return None


GROUND_TRUTH = {
    '/reflected': True,
    '/reflected_creds': True,
    '/wildcard_creds': True,
    '/null': True,
    '/post_only': True,
    '/allowlist': False,
    '/no_acao': False,
}


def _detected(target):
    sc = CORSScanner(target, session=requests.Session())
    start = time.time()
    finding = sc.scan()
    elapsed = time.time() - start
    sigs = finding.fingerprint.get('cors_signals') or []
    signals = sorted({s['signal'] for s in sigs})
    return bool(sigs), signals, elapsed


def bench_local():
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    results = {}
    try:
        for endpoint, vulnerable in GROUND_TRUTH.items():
            url = f"http://127.0.0.1:{port}{endpoint}"
            detected, signals, elapsed = _detected(url)
            results[endpoint] = {
                'vulnerable': vulnerable,
                'detected': detected,
                'signals': signals,
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
    dr = round((len(tp) / vuln_total) * 100, 1) if vuln_total else 0.0
    all_scans = [v['scan_s'] for v in results.values()]
    avg = round(sum(all_scans) / len(all_scans), 3) if all_scans else 0.0
    return {'true_positives': len(tp), 'false_positives': len(fp),
            'false_negatives': len(fn), 'true_negatives': len(tn),
            'detection_rate_pct': dr, 'avg_scan_s': avg,
            'fp_endpoints': sorted(fp), 'fn_endpoints': sorted(fn)}


def run_external(targets):
    rows = []
    for url in targets:
        try:
            detected, signals, elapsed = _detected(url)
        except Exception as e:
            rows.append({'target': url, 'detected': None, 'signals': [],
                         'scan_s': None, 'error': str(e)})
            continue
        rows.append({'target': url, 'detected': detected, 'signals': signals,
                     'scan_s': round(elapsed, 3)})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--targets', nargs='*', default=[])
    ap.add_argument('--out', default='reports/cors_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    summary = summarize(results)
    external = run_external(args.targets) if args.targets else []

    report = {
        'scanner': 'CORS configuration (Phase 3.8)',
        'fixture': 'local deterministic CORS fixture',
        'summary': summary,
        'per_endpoint': results,
        'external': external,
    }
    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print('\n=== CORS benchmark (Phase 3.8) ===')
    print(f"true positives   : {summary['true_positives']}")
    print(f"false positives  : {summary['false_positives']} {summary['fp_endpoints']}")
    print(f"false negatives  : {summary['false_negatives']} {summary['fn_endpoints']}")
    print(f"true negatives   : {summary['true_negatives']}")
    print(f"detection rate   : {summary['detection_rate_pct']}%")
    print(f"average scan time: {summary['avg_scan_s']}s")
    for ep, r in results.items():
        print(f"  {ep:16s} vuln={r['vulnerable']} detected={r['detected']} "
              f"sig={r['signals']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())