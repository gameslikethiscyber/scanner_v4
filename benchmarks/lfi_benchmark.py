"""
LFI backbone benchmark (SOP Phase 3.4).

Self-contained offline benchmark used to measure every scanner upgrade:

  - true positives   (vulnerable fixtures detected)
  - true negatives   (clean fixtures correctly not flagged)
  - false positives  (clean flagged as vulnerable)
  - false negatives  (vulnerable missed)
  - detection rate   TP / (TP + FN)
  - average scan time

The suite stands up a local ThreadingHTTPServer that emulates several server
sides: a POSIX traversal endpoint, a Windows endpoint, a shadow-file endpoint,
an encoding-only (bypass) endpoint, plus two negative controls:

  - /baseline  a page that UNCONDITIONALLY renders "root:x:" on every request
               (including the benign baseline) -- the scanner must NOT flag it
               because the marker is never introduced by an injected traversal;
  - /clean     a normal page with no markers.

Usage:
    python -m benchmarks.lfi_benchmark
    python -m benchmarks.lfi_benchmark --targets https://juice.local/
"""

import os
import sys
import time
import json
import argparse
import threading
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners.lfi import LFIScanner
import requests

POSIX_BODY = ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
              "localhost.localdomain\nroot:*:17885:0:99999:7:::\n"
              "DOCUMENT_ROOT=/var/www\n")
WIN_BODY = ("[extensions]\nfor 16-bit app support\n[fonts]\n"
            "[boot loader]\n[drivers32]\n")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def route(self):
        parsed = urlparse(self.path)
        qargs = parse_qs(parsed.query)
        v = next(iter(qargs.values()), [""])[0]
        return parsed.path, v

    def _respond(self, status, body):
        payload = body.encode('utf-8', 'replace')
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        try:
            path, v = self.route()
        except Exception:
            path, v = "/", ""

        # A benign baseline value is exactly "probe_LFI" (never a file read).
        is_baseline = (v == 'probe_LFI')

        if path == '/baseline':
            # UNCONDITIONAL disclosure: the page always shows passwd markers,
            # even for the benign baseline request. Must NOT be flagged.
            return self._respond(200, POSIX_BODY)

        if not v or is_baseline:
            return self._respond(200, "<html><body>ok</body></html>")

        if path == '/clean':
            return self._respond(200, "<html><body>ok</body></html>")
        if path == '/win':
            return self._respond(200, WIN_BODY)
        if path == '/encoded':
            # only the encoded variants carry a '%' marker; plain traversal
            # (e.g. ../../../etc/passwd) is stripped by a WAF/input filter.
            return self._respond(200, POSIX_BODY if '%' in v
                                 else "<html><body>ok</body></html>")
        # /posix, /shadow: any file-ish input is read into the include.
        return self._respond(200, POSIX_BODY)

    def do_POST(self):
        return self.do_GET()


GROUND_TRUTH = {
    '/posix': True,     # POSIX /etc/passwd + /etc/shadow + /etc/hosts
    '/shadow': True,    # shadow markers disclosed
    '/win': True,       # Windows win.ini / system.ini / boot.ini
    '/encoded': True,   # WAF-filtered plain traversal, passes only when encoded
    '/baseline': False,  # unconditional marker in baseline -> must NOT fire
    '/clean': False,     # normal page -> must NOT fire
}


def _detected(target):
    sc = LFIScanner(target, session=requests.Session())
    start = time.time()
    finding = sc.scan()
    elapsed = time.time() - start
    sigs = finding.fingerprint.get('lfi_signals') or []
    techniques = sorted({s['technique'] for s in sigs})
    files = finding.fingerprint.get('files_disclosed') or []
    return bool(sigs), techniques, files, elapsed


def bench_local(port=None):
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    results = {}
    try:
        for endpoint, vulnerable in GROUND_TRUTH.items():
            url = f"http://127.0.0.1:{port}{endpoint}?file=page"
            detected, techniques, files, elapsed = _detected(url)
            results[endpoint] = {
                'vulnerable': vulnerable,
                'detected': detected,
                'techniques': techniques,
                'files': files,
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
            detected, techniques, files, elapsed = _detected(url)
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
    ap.add_argument('--out', default='reports/lfi_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    summary = summarize(results)
    external = run_external(args.targets) if args.targets else []

    report = {
        'scanner': 'LFI detection accuracy (Phase 3.4)',
        'fixture': 'local deterministic LFI fixture',
        'summary': summary,
        'per_endpoint': results,
        'external': external,
    }
    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print('\n=== LFI benchmark (Phase 3.4) ===')
    print(f"true positives   : {summary['true_positives']}")
    print(f"false positives  : {summary['false_positives']} {summary['fp_endpoints']}")
    print(f"false negatives  : {summary['false_negatives']} {summary['fn_endpoints']}")
    print(f"true negatives   : {summary['true_negatives']}")
    print(f"detection rate   : {summary['detection_rate_pct']}%")
    print(f"average scan time: {summary['avg_scan_s']}s")
    for ep, r in results.items():
        print(f"  {ep:9s} vuln={r['vulnerable']} detected={r['detected']} "
              f"tech={r['techniques']} files={r['files']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())