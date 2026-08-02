"""
Headers Security benchmark (Phase 3.10 quality pass).

Deterministic local fixture serving realistic header policies. Measures
REDUNDANT EVIDENCE elimination: a single server policy must be reported once,
not duplicated by both the analyzer and a local re-check.

Endpoints (expectation):
  /good          all security headers present & valid ........... 0 issues
  /csp_weak      CSP allows unsafe-inline (no nonce) ............ 1 issue
  /hsts_weak     HSTS max-age below 1 year ..................... 1 issue
  /hsts_good     HSTS max-age >= 1 year ........................ 0 issues
  /xfo_missing   X-Frame-Options & X-Content-Type-Options gone . 2 issues

Usage:
    python -m benchmarks.headers_benchmark
"""

import os
import sys
import json
import argparse
import threading
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.evidence import EvidenceLevel  # noqa: F401  (kept for parity checks)
from scanners.headers import HeadersScanner
import requests

BASE_GOOD = {
    'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=()',
    'X-XSS-Protection': '1; mode=block',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
}


def _copy(drop=()):
    return {k: v for k, v in BASE_GOOD.items() if k not in drop}


POLICIES = {
    'good': _copy(),
    'csp_weak': {**{k: v for k, v in BASE_GOOD.items()
                    if k != 'Content-Security-Policy'},
                 'Content-Security-Policy':
                     "default-src 'self' 'unsafe-inline'; script-src 'self'"},
    'hsts_weak': {**{k: v for k, v in BASE_GOOD.items()
                     if k != 'Strict-Transport-Security'},
                  'Strict-Transport-Security': 'max-age=604800'},
    'hsts_missing': _copy(('Strict-Transport-Security',)),
    'xfo_missing': _copy(('X-Frame-Options', 'X-Content-Type-Options')),
}

GROUND_TRUTH = {
    'good': {'csp_dup': 0, 'hsts_dup': 0},
    'csp_weak': {'csp_dup': 1, 'hsts_dup': 0},
    'hsts_weak': {'csp_dup': 0, 'hsts_dup': 1},
    'hsts_missing': {'csp_dup': 0, 'hsts_dup': 1},
    'xfo_missing': {'csp_dup': 0, 'hsts_dup': 0},
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        mode = urlparse(self.path).path.strip('/').split('/')[0]
        headers = POLICIES.get(mode, {})
        body = b'index'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_HEAD = do_GET


def _dup_count(f, needle):
    neg = [e for e in f.evidence if getattr(e, 'level', None) in (
        EvidenceLevel.LIKELY, EvidenceLevel.POSSIBLE, EvidenceLevel.UNKNOWN)]
    return sum(1 for e in neg if needle in (e.description or '').lower())


def _measure(target):
    scanner = HeadersScanner(target, session=requests.Session())
    f = scanner.scan()
    return {'csp_dup': _dup_count(f, 'unsafe-inline'),
            'hsts_dup': _dup_count(f, 'strict-transport')}


def bench_local():
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    results = {}
    try:
        for mode, expected in GROUND_TRUTH.items():
            url = f"http://127.0.0.1:{port}/{mode}"
            r = _measure(url)
            r['expected'] = expected
            results[mode] = r
    finally:
        httpd.shutdown()
        httpd.server_close()
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='reports/headers_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as fh:
        json.dump({'scanner': 'Headers security (Phase 3.10)',
                   'per_endpoint': results}, fh, indent=2)

    print('\n=== Headers Security benchmark (Phase 3.10) ===')
    total = 0
    dup_bad = 0
    for ep, r in results.items():
        c_ok = r['csp_dup'] == r['expected']['csp_dup']
        h_ok = r['hsts_dup'] == r['expected']['hsts_dup']
        flag = 'OK' if (c_ok and h_ok) else 'DUP'
        if not (c_ok and h_ok):
            dup_bad += 1
        print(f"  {ep:14s} {flag} csp={r['csp_dup']}/{r['expected']['csp_dup']} "
              f"hsts={r['hsts_dup']}/{r['expected']['hsts_dup']}")
        total += r['csp_dup'] + r['hsts_dup']
    print(f"dedup-satisfied: {'yes' if dup_bad == 0 else 'no'} "
          f"(violations={dup_bad})")
    print(f"total repeated CSP/HSTS issue evidence: {total}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())