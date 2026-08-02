"""
SSTI backbone benchmark (SOP Phase 3.5).

Self-contained offline benchmark used to measure every scanner upgrade:

  - true positives   (vulnerable fixtures detected)
  - true negatives   (clean fixtures correctly not flagged)
  - false positives  (clean flagged as vulnerable)
  - false negatives  (vulnerable missed)
  - detection rate   TP / (TP + FN)
  - average scan time

The suite stands up a local ThreadingHTTPServer that emulates several server
sides: a generic arithmetic template endpoint, a FreeMarker-only endpoint whose
responses also surface a real engine marker (fingerprint correlation), plus
three negative controls:

  - /fp_echo      echoes the raw input verbatim (never evaluating) -- the
                  template magic numbers must NOT appear;
  - /fp_baseline  statically prints "49" and "72" in every response (including
                  the benign baseline) -- must NOT fire (Phase 3.5 guard);
  - /clean        a normal page.

Usage:
    python -m benchmarks.ssti_benchmark
    python -m benchmarks.ssti_benchmark --targets https://juice.local/
"""

import os
import sys
import time
import json
import argparse
import threading
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners.ssti import SSTIScanner
import requests


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
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        try:
            path, v = self.route()
        except Exception:
            path, v = "/", ""
        base = "<html><body>ok</body></html>"

        if path == '/clean':
            return self._respond(200, base)
        if path == '/fp_baseline':
            # static copy always contains both arithmetic products
            return self._respond(200, "<html><body>49 devices, 72 nodes, "
                                      "localhost</body></html>")
        if path == '/fp_echo':
            # echoes the literal payload, never evaluates
            return self._respond(200, f"<html><body>you typed: {v}</body></html>")

        ev = None
        if '7*7' in v:
            ev = '49'
        elif '8*9' in v:
            ev = '72'
        if ev is None:
            return self._respond(200, base)
        if ev and path == '/fm' and not v.lstrip().startswith('${'):
            # FreeMarker-only endpoint: ignore other engines' syntax
            return self._respond(200, base)
        if path == '/fm':
            body = ("<html><pre>result: %s</pre>"
                    "<b>FreeMarker template error: expected hash</b></html>" % ev)
            return self._respond(200, body)
        return self._respond(200, f"<html><body>result: {ev}</body></html>")

    def do_POST(self):
        return self.do_GET()


GROUND_TRUTH = {
    '/math': True,        # plain template engine arithmetic
    '/fm': True,          # freemarker-only + engine marker fingerprint
    '/fp_echo': False,    # echoes input verbatim, must NOT evaluate
    '/fp_baseline': False,  # statically prints 49/72, must NOT fire
    '/clean': False,       # normal page
}


def _detected(target):
    sc = SSTIScanner(target, session=requests.Session())
    start = time.time()
    finding = sc.scan()
    elapsed = time.time() - start
    engines = finding.fingerprint.get('engines') or []
    sigs = finding.fingerprint.get('ssti_signals') or []
    errors = finding.fingerprint.get('ssti_errors') or []
    ev = finding.fingerprint.get('engine_evidence') or []
    confirmed = bool(engines or sigs)
    flagged = confirmed or bool(errors)
    return flagged, engines, errors, ev, elapsed


def bench_local(port=None):
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    results = {}
    try:
        for endpoint, vulnerable in GROUND_TRUTH.items():
            url = f"http://127.0.0.1:{port}{endpoint}?name=x"
            detected, engines, errors, ev, elapsed = _detected(url)
            results[endpoint] = {
                'vulnerable': vulnerable,
                'detected': detected,
                'engines': engines,
                'errors': [e['pattern'] for e in errors],
                'consistent_engines': sorted({e['engine'] for e in ev
                                              if e.get('fingerprint_consistent')}),
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
            detected, engines, errors, ev, elapsed = _detected(url)
        except Exception as e:
            rows.append({'target': url, 'detected': None, 'engines': [],
                         'scan_s': None, 'error': str(e)})
            continue
        rows.append({'target': url, 'detected': detected, 'engines': engines,
                     'scan_s': round(elapsed, 3)})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--targets', nargs='*', default=[])
    ap.add_argument('--out', default='reports/ssti_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    summary = summarize(results)
    external = run_external(args.targets) if args.targets else []

    report = {
        'scanner': 'SSTI detection accuracy (Phase 3.5)',
        'fixture': 'local deterministic SSTI fixture',
        'summary': summary,
        'per_endpoint': results,
        'external': external,
    }
    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print('\n=== SSTI benchmark (Phase 3.5) ===')
    print(f"true positives   : {summary['true_positives']}")
    print(f"false positives  : {summary['false_positives']} {summary['fp_endpoints']}")
    print(f"false negatives  : {summary['false_negatives']} {summary['fn_endpoints']}")
    print(f"true negatives   : {summary['true_negatives']}")
    print(f"detection rate   : {summary['detection_rate_pct']}%")
    print(f"average scan time: {summary['avg_scan_s']}s")
    for ep, r in results.items():
        print(f"  {ep:12s} vuln={r['vulnerable']} detected={r['detected']} "
              f"engines={r['engines']} gem={r['consistent_engines']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())