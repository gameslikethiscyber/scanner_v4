from scanners.base import BaseScanner

class HostHeaderScanner(BaseScanner):
    def scan(self):
        print("   [+] Host Header Injection")
        try:
            baseline = self.get(self.core.target_url)
            evil = 'evil-attacker.com'
            r = self.get(self.core.target_url, headers={'Host': evil})

            usage = []
            if f'href="http://{evil}' in r.text: usage.append('links')
            if f'action="http://{evil}' in r.text: usage.append('form actions')
            if f'@{evil}' in r.text: usage.append('emails')
            if evil in r.text and evil not in baseline.text: usage.append('reflected')

            if usage:
                ev = f"Host: {evil}\nUsed in: {', '.join(usage)}"
                self.add('Confirmed Host Header Injection', 'HIGH', f"Host used in: {', '.join(usage)}", 'Validate Host header', ev, 80, 'A03:2021', 'CWE-644', 'Host Header', 'confirmed')
            else:
                print("      OK Host header validated")
        except:
            pass
