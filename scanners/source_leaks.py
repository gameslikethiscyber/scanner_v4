from scanners.base import BaseScanner
import re

class SourceLeakScanner(BaseScanner):
    def scan(self):
        print("   [+] Source Code Leaks")
        try:
            r = self.get(self.core.target_url)
            text = r.text

            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
            if emails:
                u = list(set(emails))[:5]
                ev = f"Emails: {', '.join(u)}"
                self.add('Public Emails Found', 'LOW', f'Emails: {", ".join(u)}', 'Remove from public code', ev, 100, 'A05:2021', 'CWE-200', 'Info Disclosure', 'bestpractice')

            patterns = [
                (r'api[_-]?key\s*[:=]\s*[a-zA-Z0-9]{16,}', 'API Key'),
                (r'AKIA[0-9A-Z]{16}', 'AWS Key'),
                (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Token'),
            ]
            for pat, name in patterns:
                m = re.findall(pat, text, re.I)
                if m:
                    ev = f"Pattern matched: {pat}\nFirst: {m[0][:50]}"
                    self.add(f'Hardcoded {name}', 'CRITICAL', f'{name} in source', 'Never hardcode secrets', ev, 95, 'A05:2021', 'CWE-798', 'Info Disclosure', 'confirmed')
                    break

            ips = re.findall(r'(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.[\d.]+', text)
            if ips:
                u = list(set(ips))[:5]
                ev = f"IPs: {', '.join(u)}"
                self.add('Internal IPs Disclosed', 'MEDIUM', f'IPs: {", ".join(u)}', 'Remove from public', ev, 100, 'A05:2021', 'CWE-200', 'Info Disclosure', 'bestpractice')
        except:
            pass
