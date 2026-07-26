from scanners.base import BaseScanner
from urllib.parse import urljoin

class SecurityTxtScanner(BaseScanner):
    def scan(self):
        print("   [+] security.txt")
        try:
            url = urljoin(self.core.target_url, '/.well-known/security.txt')
            r = self.get(url)
            if r.status_code == 200 and 'contact:' in r.text.lower():
                print("      OK security.txt found")
            elif r.status_code == 200:
                ev = f"URL: {url}\nStatus: 200\nMissing 'contact:'"
                self.add('Incomplete security.txt', 'LOW', 'Missing Contact:', 'Add Contact:', ev, 100, 'A05:2021', 'CWE-200', 'Best Practices', 'bestpractice')
            else:
                ev = f"URL: {url}\nStatus: {r.status_code}"
                self.add('Missing security.txt', 'LOW', 'Not found', 'Create security.txt', ev, 100, 'A05:2021', 'CWE-200', 'Best Practices', 'bestpractice')
        except:
            pass
