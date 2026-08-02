"""
Sensitive Files benchmark (Phase 3.10 quality pass).

Deterministic local fixture serving realistic benign and genuinely-sensitive
files. Measures reduction of FALSE POSITIVES (public / benign files being
report as "exposed sensitive files") while preserving TRUE POSITIVES.

Sites (truth):
  /clean    serves only benign config files (robots/README/LICENSE/package/
            sitemap/.gitignore/Makefile) ...................... clean (not vuln)
  /env      serves a real .env with DB credentials ........... vuln
  /git      serves a real .git/config + .htpasswd ........... vuln
  /wp       serves a real wp-config.php ...................... vuln
  /empty    serves nothing (all 404) ......................... clean

Usage:
    python -m benchmarks.sensitive_files_benchmark
"""

import os
import sys
import time
import json
import argparse
import threading
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanners.sensitive_files import SensitiveFilesScanner
import requests

# Benign / public content that must NOT be reported as an exposure.
BENIGN = {
    'robots.txt': 'User-agent: *\nDisallow: /admin\n',
    'LICENSE': 'MIT License\nCopyright (c) 2023\n',
    'README.md': '# Usage\n\nRun `install` to deploy.\n',
    'package.json': '{"name": "app", "version": "1.0.0", "dependencies": {}}',
    'sitemap.xml': '<?xml version="1.0"?><urlset xmlns=""></urlset>',
    'Makefile': 'install:\n\techo installing\ntest:\n\techo testing\n',
    '.gitignore': 'node_modules/\n.env\n',
}

# Real sensitive content that must be reported.
SENSITIVE = {
    '.env': 'DB_PASSWORD=super_secret_1\nSECRET_KEY=abcdef\nAPP_KEY=xyz\n',
    'config.php': '<?php $db_password = "admin123"; ?>\n',
    'settings.py': 'SECRET_KEY = "s3cr3t"\nDATABASES = {}\n',
    '.git/config': '[remote "origin"]\n\turl = https://github.com/acme/app\n',
    '.git/HEAD': 'ref: refs/heads/main\n',
    '.htpasswd': 'webmaster:$apr1$abc/xyz.\n',
    'wp-config.php': "define('DB_PASSWORDFRIED', 'p@ssw0rd');\n",
}

SITES = {
    'clean': BENIGN,
    'env': {'.env': SENSITIVE['.env']},
    'git': {'.git/config': SENSITIVE['.git/config'],
            '.htpasswd': SENSITIVE['.htpasswd']},
    'wp': {'wp-config.php': SENSITIVE['wp-config.php']},
    'empty': {},
}

GROUND_TRUTH = {
    'clean': False,
    'env': True,
    'git': True,
    'wp': True,
    'empty': False,
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        parts = urlparse(self.path).path.strip('/').split('/')
        site = parts[0] if parts else ''
        file = '/'.join(parts[1:]) if len(parts) > 1 else ''
        content = SITES.get(site, {}).get(file)
        if content is None:
            self.send_response(404)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', '9')
            self.end_headers()
            self.wfile.write(b'not found')
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def do_HEAD(self):
        self.do_GET()


def _detected(target):
    sc = SensitiveFilesScanner(target, session=requests.Session())
    start = time.time()
    finding = sc.scan()
    elapsed = time.time() - start
    exposed = finding.fingerprint.get('exposed_files') or []
    return bool(exposed), exposed, elapsed


def bench_local():
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    results = {}
    try:
        for site, vulnerable in GROUND_TRUTH.items():
            url = f"http://127.0.0.1:{port}/{site}"
            detected, exposed, elapsed = _detected(url)
            results[site] = {
                'vulnerable': vulnerable,
                'detected': detected,
                'exposed': exposed,
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
    precision = round((len(tp) / (len(tp) + len(fp))) * 100, 1) if (len(tp) + len(fp)) else 0.0
    return {'true_positives': len(tp), 'false_positives': len(fp),
            'false_negatives': len(fn), 'true_negatives': len(tn),
            'detection_rate_pct': dr, 'precision_pct': precision,
            'fp_endpoints': sorted(fp), 'fn_endpoints': sorted(fn)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tgt', nargs='*', default=[])
    ap.add_argument('--out', default='reports/sensitive_files_benchmark.json')
    args = ap.parse_args()

    results = bench_local()
    summary = summarize(results)
    outdir = os.path.dirname(args.out) or '.'
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump({'scanner': 'Sensitive files (Phase 3.10)',
                   'fixture': 'local deterministic sensitive-files fixture',
                   'summary': summary, 'per_endpoint': results}, f, indent=2)

    print('\n=== Sensitive Files benchmark (Phase 3.10) ===')
    print(f"true positives   : {summary['true_positives']}")
    print(f"false positives  : {summary['false_positives']} {summary['fp_endpoints']}")
    print(f"false negatives  : {summary['false_negatives']} {summary['fn_endpoints']}")
    print(f"true negatives   : {summary['true_negatives']}")
    print(f"detection rate   : {summary['detection_rate_pct']}%")
    print(f"precision        : {summary['precision_pct']}%")
    for ep, r in results.items():
        print(f"  {ep:12s} vuln={r['vulnerable']} detected={r['detected']} "
              f"exposed={r['exposed']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())