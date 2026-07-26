from scanners.base import BaseScanner
from urllib.parse import urljoin, quote

class LFIScanner(BaseScanner):
    def scan(self):
        print("   [+] LFI / RFI")
        lfi_payloads = [
            ('../../../etc/passwd', 'root:'),
            ('....//....//....//etc/passwd', 'root:'),
            ('..%2f..%2f..%2fetc%2fpasswd', 'root:'),
            ('/etc/passwd', 'root:'),
        ]
        params = ['file', 'page', 'path', 'include', 'view']
        found = False

        for p in params:
            for payload, indicator in lfi_payloads:
                try:
                    url = f"{self.core.target_url}/?{p}={quote(payload)}"
                    r = self.get(url)
                    if indicator in r.text:
                        snippet = r.text[max(0, r.text.find(indicator)-30):r.text.find(indicator)+60]
                        ev = f"Parameter: {p}\nPayload: {payload}\nIndicator: '{indicator}'\nSnippet: {snippet}"
                        self.add(f'Confirmed LFI: {p}', 'CRITICAL', 'LFI confirmed', 'Whitelist allowed files', ev, 95, 'A01:2021', 'CWE-98', 'LFI/RFI', 'confirmed')
                        found = True
                        break
                except:
                    pass
            if found: break

        if not found:
            try:
                payload = 'https://raw.githubusercontent.com/github/hello-world/master/README'
                r = self.get(f"{self.core.target_url}/?file={quote(payload)}")
                if 'hello-world' in r.text.lower():
                    ev = f"Parameter: file\nPayload: {payload}\nExternal content: YES"
                    self.add('Confirmed RFI: file', 'CRITICAL', 'RFI confirmed', 'Disable allow_url_include', ev, 90, 'A10:2021', 'CWE-98', 'LFI/RFI', 'confirmed')
                    found = True
            except:
                pass

        if not found:
            print("      OK No LFI/RFI")
