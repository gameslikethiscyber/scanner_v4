"""
SSRF backbone benchmark (SOP Phase 3.3).

Self-contained offline benchmark used to measure every scanner upgrade:

  - true positives   (vulnerable fixtures detected)
  - true negatives   (clean fixtures correctly not flagged)
  - false positives  (clean flagged as vulnerable)
  - false negatives  (vulnerable missed)
  - detection rate   TP / (TP + FN)
  - average scan time

The suite stands up a local ThreadingHTTPServer that simulates: a cloud metadata
endpoint (AWS IMDS / Azure / GCP), an internal-fetch endpoint, a URL-fetch error
endpoint, and a server-side redirect to an internal host, plus two clean control
pages (a URL echoer and a generic 404 page) that the scanner must NOT flag.

Provide external targets on argv (e.g. OWASP Juice Shop, DVWA, bWAPP) to also
record their detection/time.

Usage:
    python -m benchmarks.ssrf_benchmark
    python -m benchmarks.ssrf_benchmark --targets https://juice.local/
"""

import os
import sys
import time
import json
import argparse
import threading
from urllib.parse import urlparse, parse_qs, quote
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners.ssrf import SSRFScanner
import requests

AWS_BODY = "ami-id: ami-0abc\ninstance-id: i-800000\nlocal-ipv4: 10.0.0.9\n"
AZURE_BODY = ('{"compute":{"subscriptionId":"sub-1","resourceGroupId":"rg-2",'
              '"vmId":"vm-3"},"service":{}}')
GCP_BODY = "instanceId/\nprojectId\noslogin/\ninstance/\n"


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

        if path == '/meta':
            if 'metadata.google.internal' in v and \
               self.headers.get('Metadata-Flavor') == 'Google':
                return self._respond(200, GCP_BODY)
            if 'metadata/instance' in v:
                return self._respond(200, AZURE_BODY)
            if '169.254.169.254' in v:
                return self._respond(200, AWS_BODY)
            return self._respond(200, "<p>ok</p>")
        if path == '/err':
            if v in ('http://127.0.0.1:1/', 'http://169.254.169.254:65535/',
                     'http://nonexistent.invalid/'):
                return self._respond(200, "Error: Connection refused")
            return self._respond(200, "<p>ok</p>")
        if path == '/icols':
            if any(h in v for h in ('127.0.0.', 'localhost', '0.0.0.0',
                                    '10.1.2.3', '192.168.1.1', '172.16.0.1')):
                return self._respond(200, "<html>" + "z" * 800 + "</html>")
            return self._respond(200, "<p>ok</p>")
        if path == '/redir':
            if '127.0.0.1' in v or '[::1]' in v or '169.254.169.254' in v:
                r_body = "<html></html>"
                self.send_response(302)
                self.send_header('Location', 'http://10.0.0.99/')
                payload = r_body.encode('utf-8')
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            return self._respond(200, "<p>ok</p>")
        if path == '/echo':
            return self._respond(200, f"<p>fetched: {quote(v)}</p>")
        if path == '/clean404':
            return self._respond(404, ("<html><head><title>404</title></head>"
                                       "<body><h1>404 Not Found</h1></body></html>"))
        return self._respond(200, "<p>ok</p>")

    def do_POST(self):
        return self.do_GET()


GROUND_TRUTH = {
    '/meta': True,      # cloud metadata (AWS/Azure/GCP)
    '/icols': True,     # internal host fetch
    '/err': True,       # error-signature fetch
    '/redir': True,     # server-side redirect to internal
    '/echo': False,     # URL echo page must NOT fire
    '/clean404': False,  # generic 404 must NOT fire
}


def _detected(target):
    sc = SSRFScanner(target, session=requests.Session())
    start = time.time()
    finding = sc.scan()
    elapsed = time.time() - start
    sigs = finding.fingerprint.get('ssrf_signals') or []
    techniques = sorted({s['technique'] for s in sigs})
    provider = finding.fingerprint.get('cloud_provider') or []
    return bool(sigs), techniques, provider, elapsed


def bench_local(port=None):
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    results = {}
    try:
        for endpoint, vulnerable in GROUND_TRUTH.items():
            url = f"http://127.0.0.1:{port}{endpoint}?url=probe"
            detected, techniques, provider, elapsed = _detected(url)
            results[endpoint] = {
                'vulnerable': vulnerable,
                'detected': detected,
                'techniques': techniques,
                'provider': provider,
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
            detected, techniques, provider, elapsed = _detected(url)
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
    ap.add_argument('--out', default='reports/ssrf_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    summary = summarize(results)
    external = run_external(args.targets) if args.targets else []

    report = {
        'scanner': 'SSRF detection accuracy (Phase 3.3)',
        'fixture': 'local deterministic SSRF fixture',
        'summary': summary,
        'per_endpoint': results,
        'external': external,
    }
    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print('\n=== SSRF benchmark (Phase 3.3) ===')
    print(f"true positives   : {summary['true_positives']}")
    print(f"false positives  : {summary['false_positives']} {summary['fp_endpoints']}")
    print(f"false negatives  : {summary['false_negatives']} {summary['fn_endpoints']}")
    print(f"true negatives   : {summary['true_negatives']}")
    print(f"detection rate   : {summary['detection_rate_pct']}%")
    print(f"average scan time: {summary['avg_scan_s']}s")
    for ep, r in results.items():
        print(f"  {ep:9s} vuln={r['vulnerable']} detected={r['detected']} "
              f"tech={r['techniques']} provider={r['provider']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())