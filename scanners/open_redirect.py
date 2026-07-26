from scanners.base import BaseScanner
from urllib.parse import quote

class OpenRedirectScanner(BaseScanner):
    def scan(self):
        print("   [+] Open Redirect")
        payloads = ['https://evil.com', '//evil.com']
        params = ['url', 'redirect', 'return', 'next', 'goto']
        found = False

        for p in params:
            for payload in payloads:
                try:
                    url = f"{self.core.target_url}/?{p}={quote(payload)}"
                    r = self.get(url, allow_redirects=False)
                    loc = r.headers.get('Location', '')
                    if r.status_code in [301, 302, 307, 308] and 'evil.com' in loc:
                        ev = f"Parameter: {p}\nPayload: {payload}\nStatus: {r.status_code}\nLocation: {loc}"
                        self.add(f'Confirmed Open Redirect: {p}', 'HIGH', 'Redirects to arbitrary URLs', 'Whitelist destinations', ev, 95, 'A01:2021', 'CWE-601', 'Open Redirect', 'confirmed')
                        found = True
                        break
                except:
                    pass
            if found: break

        if not found:
            print("      OK No open redirect")
