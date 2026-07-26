from scanners.base import BaseScanner

class HeaderScanner(BaseScanner):
    def scan(self):
        print("   [+] Security Headers")
        try:
            r = self.get(self.core.target_url)
            self.core.base_response = r
            h = {k.lower(): v for k, v in r.headers.items()}
            hdrs = "\n".join([f"  {k}: {v}" for k, v in r.headers.items()])

            checks = [
                ('strict-transport-security', 'Missing HSTS Header', 'MEDIUM', 'Add HSTS: max-age=31536000; includeSubDomains', 'A05:2021', 'CWE-693', 'misconfig'),
                ('content-security-policy', 'Missing CSP Header', 'MEDIUM', 'Add Content-Security-Policy header', 'A05:2021', 'CWE-693', 'misconfig'),
                ('x-frame-options', 'Missing X-Frame-Options', 'MEDIUM', 'Add X-Frame-Options: DENY', 'A05:2021', 'CWE-693', 'misconfig'),
                ('x-content-type-options', 'Missing X-Content-Type-Options', 'MEDIUM', 'Add X-Content-Type-Options: nosniff', 'A05:2021', 'CWE-693', 'misconfig'),
                ('referrer-policy', 'Missing Referrer-Policy', 'LOW', 'Add Referrer-Policy', 'A05:2021', 'CWE-200', 'misconfig'),
                ('permissions-policy', 'Missing Permissions-Policy', 'LOW', 'Add Permissions-Policy header', 'A05:2021', 'CWE-200', 'misconfig'),
            ]

            for header, title, sev, fix, owasp, cwe, ftype in checks:
                if header not in h:
                    ev = f"GET {self.core.target_url}\n\nResponse Headers:\n{hdrs}\n\nMissing: {header.upper()}"
                    self.add(title, sev, f"'{header}' header not set", fix, ev, 100, owasp, cwe, 'Security Headers', ftype)

            if 'content-security-policy' in h:
                csp = h['content-security-policy']
                if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                    ev = f"CSP: {csp[:200]}"
                    self.add('Weak CSP (unsafe-inline/eval)', 'HIGH', 'CSP allows dangerous directives', "Remove 'unsafe-inline'", ev, 95, 'A05:2021', 'CWE-693', 'Security Headers', 'misconfig')

            for hdr in ['server', 'x-powered-by', 'x-generator']:
                if hdr in h:
                    ev = f"{hdr}: {h[hdr]}"
                    self.add(f'Info Disclosure: {hdr.upper()}', 'LOW', f"Header reveals: {h[hdr]}", f'Remove {hdr}', ev, 100, 'A05:2021', 'CWE-200', 'Information Disclosure', 'bestpractice')
        except Exception as e:
            pass
