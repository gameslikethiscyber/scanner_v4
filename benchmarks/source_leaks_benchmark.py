"""
Source Code Leaks benchmark (Phase 3.10 quality pass).

Deterministic local fixture measuring FALSE-POSITIVE reduction: ambient /
informational categories (Emails, Comments, Debug Information, Source Maps)
must NOT be reported as leaks on an ordinary public page unless a genuine,
confirmed secret/config leak is present.

Endpoints (truth):
  /contact    public page with a contact email + build comment .. clean
  /debug      page with only a stack trace ..................... clean
  /api_key    page leaking an AWS access key .................. vuln
  /db_cred    page leaking a DB password ...................... vuln
  /pk         page containing a private key ................... vuln
  /git        page referencing .git/config ................... vuln

Usage:
    python -m benchmarks.source_leaks_benchmark
"""

import os
import sys
import json
import argparse
import threading
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners.source_leaks import SourceLeaksScanner
import requests

PAGES = {
    'home': '<!DOCTYPE html><html><body>Welcome! '
            'Contact: <a href="mailto:info@example.com">info@example.com</a>'
            '<!-- built by: dev-squad v1.2 --></body></html>',
    'debug': '<html><pre>Traceback (most recent call last):\n'
             '  File "app.py", line 40, in main\n    run()\n'
             'TypeError: unsupported</pre></html>',
    'api_key': '<html><script>const AWS_ACCESS_KEY = "AKIALJ2K3H4EXAMPLE";'
               '</script></html>',
    'db_cred': '<html><script>DB_PASSWORD = "s3cr3t";</script></html>',
    'pk': '<html><pre>-----BEGIN RSA PRIVATE KEY-----\n'
          'MIIEvQIBADANBgoK8KpQ\n'
          '-----END RSA PRIVATE KEY-----</pre></html>',
    'git': '<html>deploying from <b>.git/config</b></html>',
}

GROUND_TRUTH = {
    'home': False,
    'debug': False,
    'api_key': True,
    'db_cred': True,
    'pk': True,
    'git': True,
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        mode = urlparse(self.path).path.strip('/').split('/')[0]
        body = PAGES.get(mode, '')
        self.send_response(400 if not body else 200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode('utf-8'))


def _detected(target):
    scanner = SourceLeaksScanner(target, session=requests.Session())
    finding = scanner.scan()
    leaks = finding.fingerprint.get('leak_categories') or []
    return bool(leaks), leaks


def bench_local():
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    results = {}
    try:
        for mode, vulnerable in GROUND_TRUTH.items():
            url = f"http://127.0.0.1:{port}/{mode}"
            detected, cats = _detected(url)
            results[mode] = {'vulnerable': vulnerable, 'detected': detected,
                             'categories': cats}
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
    ap.add_argument('--out', default='reports/source_leaks_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    summary = summarize(results)
    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as fh:
        json.dump({'scanner': 'Source code leaks (Phase 3.10)',
                   'summary': summary, 'per_endpoint': results}, fh, indent=2)

    print('\n=== Source Leaks benchmark (Phase 3.10) ===')
    print(f"true positives   : {summary['true_positives']}")
    print(f"false positives  : {summary['false_positives']} {summary['fp_endpoints']}")
    print(f"false negatives  : {summary['false_negatives']} {summary['fn_endpoints']}")
    print(f"true negatives   : {summary['true_negatives']}")
    print(f"detection rate   : {summary['detection_rate_pct']}%")
    print(f"precision        : {summary['precision_pct']}%")
    for ep, r in results.items():
        print(f"  {ep:8s} vuln={r['vulnerable']} detected={r['detected']} "
              f"cats={r['categories']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())