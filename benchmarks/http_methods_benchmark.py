"""
HTTP Methods benchmark (Phase 3.10 quality pass).

Deterministic local fixture testing whether dangerous HTTP methods are only
reported when they are genuinely ALLOWED. The key FP to close: a 3xx redirect
(no redirect is a method allowance) must NOT count as 'allowed'.

Modes (truth):
  /safe        GET/POST/HEAD 200 ; OPTIONS/PUT/DELETE/TRACE/CONNECT/PATCH/PURGE
               405 ......................... clean
  /trace       TRACE -> 200 (echo) .......... vulnerable (TRACE enabled)
  /put         PUT -> 200 .................. vulnerable (unsafe PUT/DELETE)
  /delete      DELETE -> 200 ............... vulnerable
  /redirect    PUT/DELETE -> 302 redirect .. clean (a 302 is not an allowance)
  /auth        PUT -> 401 (realm) .......... vulnerable (processed w/ auth)

Usage:
    python -m benchmarks.http_methods_benchmark
"""

import os
import sys
import time
import json
import argparse
import threading
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners.http_methods import HTTPMethodsScanner
import requests

METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE',
           'CONNECT', 'PATCH', 'HEAD', 'PURGE']

# mode -> {method: status}
MODES = {
    'safe': {'GET': 200, 'POST': 200, 'HEAD': 200, 'PATCH': 405, 'PUT': 405,
             'DELETE': 405, 'OPTIONS': 405, 'TRACE': 405, 'CONNECT': 405,
             'PURGE': 405},
    'wrong': {'GET': 200, 'POST': 200, 'HEAD': 200, 'OPTIONS': 200,
              'PUT': 405, 'DELETE': 405, 'TRACE': 200, 'CONNECT': 405,
              'PATCH': 405, 'PURGE': 405},
    'put': {'GET': 200, 'POST': 200, 'HEAD': 200, 'OPTIONS': 200,
            'PUT': 200, 'DELETE': 405, 'TRACE': 405, 'CONNECT': 405,
            'PATCH': 405, 'PURGE': 405},
    'delete': {'GET': 200, 'POST': 200, 'HEAD': 200, 'OPTIONS': 200,
               'PUT': 405, 'DELETE': 200, 'TRACE': 405, 'CONNECT': 405,
               'PATCH': 405, 'PURGE': 405},
    'redirect': {'GET': 200, 'POST': 200, 'HEAD': 200, 'OPTIONS': 200,
                 'PUT': 302, 'DELETE': 302, 'TRACE': 405, 'CONNECT': 405,
                 'PATCH': 405, 'PURGE': 405},
    'auth': {'GET': 200, 'POST': 200, 'HEAD': 200, 'OPTIONS': 200,
             'PUT': 401, 'DELETE': 401, 'TRACE': 405, 'CONNECT': 405,
             'PATCH': 405, 'PURGE': 405},
}

GROUND_TRUTH = {
    'safe': False,
    'wrong': True,      # TRACE enabled
    'put': True,
    'delete': True,
    'redirect': False,  # 302 is NOT an allowance (FP to fix)
    'auth': True,       # method processed behind auth
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _respond(self, body=b'ok'):
        mode = urlparse(self.path).path.strip('/').split('/')[0]
        stats = MODES.get(mode, MODES['safe'])
        status = stats.get(self.command, 405)
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain')
        if status == 302:
            self.send_header('Location', '/login')
            body = b'redirect'
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_TRACE = \
        do_CONNECT = do_PATCH = do_HEAD = do_PURGE = _respond


def _detected(target):
    scanner = HTTPMethodsScanner(target, session=requests.Session())
    start = time.time()
    finding = scanner.scan()
    elapsed = time.time() - start
    dm = finding.detection_methods or []
    allowed = (finding.fingerprint.get('allowed_methods') or [])
    return {'detected': bool(dm), 'detected_methods': dm,
            'allowed': allowed, 'scan_s': round(elapsed, 3)}


def bench_local():
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    results = {}
    try:
        for mode, vulnerable in GROUND_TRUTH.items():
            url = f"http://127.0.0.1:{port}/{mode}"
            r = _detected(url)
            r['vulnerable'] = vulnerable
            results[mode] = r
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
    precision = round((len(tp) / (len(tp) + len(fp))) * 100, 1) if (len(tp) + len(fp)) else 0.0
    return {'true_positives': len(tp), 'false_positives': len(fp),
            'false_negatives': len(fn), 'true_negatives': len(tn),
            'detection_rate_pct': dr, 'precision_pct': precision,
            'fp_endpoints': sorted(fp), 'fn_endpoints': sorted(fn)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='reports/http_methods_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    summary = summarize(results)
    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump({'scanner': 'HTTP methods (Phase 3.10)',
                   'summary': summary, 'per_endpoint': results}, f, indent=2)

    print('\n=== HTTP Methods benchmark (Phase 3.10) ===')
    print(f"true positives   : {summary['true_positives']}")
    print(f"false positives  : {summary['false_positives']} {summary['fp_endpoints']}")
    print(f"false negatives  : {summary['false_negatives']} {summary['fn_endpoints']}")
    print(f"true negatives   : {summary['true_negatives']}")
    print(f"detection rate   : {summary['detection_rate_pct']}%")
    print(f"precision        : {summary['precision_pct']}%")
    for ep, r in results.items():
        print(f"  {ep:10s} vuln={r['vulnerable']} detected={r['detected']} "
              f"dm={r['detected_methods']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())