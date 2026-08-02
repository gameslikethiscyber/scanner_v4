"""
CSRF protection benchmark (SOP Phase 3.7).

Self-contained offline benchmark to measure the v4.6.0 CSRF upgrade:

  - true positives   (weakly-protected fixtures detected)
  - true negatives   (properly-protected / clean fixtures correctly not flagged)
  - false positives  (clean flagged as vulnerable)
  - false negatives  (vulnerable missed)
  - detection rate   TP / (TP + FN)
  - average scan time

Fixtures:
  /no_token      POST form with NO anti-CSRF token; server accepts any POST
                 (including marked cross-origin); no SameSite cookie.
  /token_ignored form has a token but the server accepts POSTs without / with a
                 wrong token (token not enforced).
  /token_weak    token IS enforced but it is short + constant (weak / reused).
  /static        token enforced, random unique, cross-origin rejected -> TN.
  /samesite      no token BUT session cookie is SameSite=Lax and cross-origin is
                 rejected -> the missing-token is mitigated (v3 FP removed).
  /clean         no POST forms at all.

Usage:
    python -m benchmarks.csrf_benchmark
    python -m benchmarks.csrf_benchmark --targets https://app.local/
"""

import os
import sys
import time
import json
import argparse
import threading
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners.csrf import CSRFScanner
import requests

_nonce = [0]


def _token():
    _nonce[0] += 1
    return f"tok_{_nonce[0]:08d}_{'a' * 20}"


STATIC_TOKEN = "kFn78q2pZ9wXzY4tQ3NvL0bRdDx1"   # long, strong, constant per fixture
WEAK_TOKEN = "WEAKTOK"                              # short (8) -> weak

HTML_FORM = ("<html><body>"
             "<form method='post' action='{action}'>"
             "<input type='text' name='X'>"
             "{tok}<input type='submit'>"
             "</form></body></html>")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, body, extra_headers=None):
        payload = body.encode('utf-8', 'replace')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(payload)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _mode(self, path):
        # '/weak' keeps a token (so weak_token can fire); '/token_ignored' keeps
        # a token (so not_enforced fires); all other paths carry no token unless
        # they are the protected '/static'.
        return path

    def _page(self, path):
        if path == '/static':
            tok = f"<input type='hidden' name='_token' value='{STATIC_TOKEN}'>"
        elif path == '/weak':
            tok = f"<input type='hidden' name='csrf_token' value='{WEAK_TOKEN}'>"
        elif path == '/token_ignored':
            tok = "<input type='hidden' name='csrf_token' value='{0}TESTTOKEN_UNIQUE_1238'>"
        else:
            tok = ""
        return HTML_FORM.format(action=path, tok=tok)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/clean':
            return self._send(200, "<html><body>no forms</body></html>")
        if path == '/samesite':
            self._send(200, self._page(path),
                       {'Set-Cookie': 'sessionid=abc; Path=/; SameSite=Lax'})
            return
        return self._send(200, self._page(path))

    def _valid_csrf(self, body, path):
        if path == '/static':
            return ('_token=' in body) and (STATIC_TOKEN in body)
        if path == '/weak':
            return ('csrf_token=' in body) and (WEAK_TOKEN in body)
        return True

    def do_POST(self):
        path = urlparse(self.path).path
        origin = self.headers.get('Origin', '')
        cross = bool(origin and 'evil.com' in origin)
        body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode('utf-8', 'replace')

        if path == '/clean':
            return self._send(200, "noop")
        if path == '/static':
            if cross or not self._valid_csrf(body, path):
                return self._send(403, "<h1>CSRF verification failed</h1>")
            return self._send(200, "ok")
        if path == '/weak':
            if cross or not self._valid_csrf(body, path):
                return self._send(403, "CSRF token invalid")
            return self._send(200, "ok")
        if path == '/token_ignored':
            return self._send(200, "accepted")
        if path == '/samesite':
            if cross:
                return self._send(403, "bad origin")
            return self._send(200, "protected session")
        # /no_token
        return self._send(200, "accepted")
        if path == '/weak':
            if cross or not has_token:
                return self._send(403, "csrf failed")
            return self._send(200, "success")
        if path == '/token_ignored':
            return self._send(200, "success")   # ignores token & origin
        if path == '/samesite':
            if cross:
                return self._send(403, "bad origin")
            return self._send(200, "secure session ok")
        # /no_token
        return self._send(200, "success")


GROUND_TRUTH = {
    '/no_token': True,       # no token + accepts everything
    '/token_ignored': True,  # token present but not enforced
    '/weak': True,           # token enforced but weak / reused
    '/static': False,        # properly protected
    '/samesite': False,      # SameSite mitigates missing token
    '/clean': False,         # no forms
}


def _detected(target):
    sc = CSRFScanner(target, session=requests.Session())
    start = time.time()
    finding = sc.scan()
    elapsed = time.time() - start
    sigs = finding.fingerprint.get('csrf_signals') or []
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
            url = f"http://127.0.0.1:{port}{endpoint}"
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
    ap.add_argument('--targets', nargs='*', default=[])
    ap.add_argument('--out', default='reports/csrf_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    summary = summarize(results)
    external = run_external(args.targets) if args.targets else []

    report = {
        'scanner': 'CSRF protection (Phase 3.7)',
        'fixture': 'local deterministic CSRF fixture',
        'summary': summary,
        'per_endpoint': results,
        'external': external,
    }
    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print('\n=== CSRF benchmark (Phase 3.7) ===')
    print(f"true positives   : {summary['true_positives']}")
    print(f"false positives  : {summary['false_positives']} {summary['fp_endpoints']}")
    print(f"false negatives  : {summary['false_negatives']} {summary['fn_endpoints']}")
    print(f"true negatives   : {summary['true_negatives']}")
    print(f"detection rate   : {summary['detection_rate_pct']}%")
    print(f"average scan time: {summary['avg_scan_s']}s")
    for ep, r in results.items():
        print(f"  {ep:16s} vuln={r['vulnerable']} detected={r['detected']} "
              f"tech={r['techniques']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())