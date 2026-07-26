from scanners.base import BaseScanner
from urllib.parse import urljoin

class TechDetector(BaseScanner):
    def scan(self):
        print("   [+] Technology Detection")
        try:
            r = self.get(self.core.target_url)
            t = r.text.lower()
            h = {k.lower(): v for k, v in r.headers.items()}

            cms = []
            if 'wp-content' in t or 'wp-includes' in t:
                cms.append('WordPress')
                try:
                    rr = self.get(urljoin(self.core.target_url, '/wp-json/wp/v2/users'))
                    if rr.status_code == 200 and 'name' in rr.text:
                        ev = f"/wp-json/wp/v2/users\nStatus: {rr.status_code}"
                        self.add('WordPress User Enumeration', 'MEDIUM', 'REST API exposes users', 'Disable REST user enum', ev, 90, 'A01:2021', 'CWE-200', 'WordPress', 'confirmed')
                except:
                    pass
                try:
                    rr = self.get(urljoin(self.core.target_url, '/xmlrpc.php'))
                    if rr.status_code == 200 and 'XML-RPC' in rr.text:
                        ev = f"/xmlrpc.php\nStatus: {rr.status_code}"
                        self.add('WordPress XML-RPC Enabled', 'HIGH', 'xmlrpc.php accessible', 'Block xmlrpc.php', ev, 95, 'A05:2021', 'CWE-200', 'WordPress', 'confirmed')
                except:
                    pass

            if 'drupal' in t: cms.append('Drupal')
            if 'joomla' in t: cms.append('Joomla')
            if 'laravel' in t: cms.append('Laravel')
            if 'django' in t: cms.append('Django')
            if 'react' in t: cms.append('React')
            if 'next.js' in t or '_next' in t: cms.append('Next.js')

            if cms:
                ev = f"Detected: {', '.join(cms)}"
                self.add('Technology Stack', 'INFO', f'Tech: {", ".join(cms)}', 'Keep updated', ev, 100, 'A06:2021', 'CWE-1104', 'Technology', 'bestpractice')
        except:
            pass
