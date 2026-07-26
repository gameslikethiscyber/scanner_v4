from scanners.base import BaseScanner
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

class SensitiveFileScanner(BaseScanner):
    def scan(self):
        print("   [+] Sensitive Files")
        paths = [
            ('/.env', 'CRITICAL'), ('/.git/config', 'CRITICAL'), ('/.git/HEAD', 'CRITICAL'),
            ('/.svn/entries', 'CRITICAL'), ('/.htpasswd', 'CRITICAL'),
            ('/backup.zip', 'HIGH'), ('/backup.sql', 'HIGH'), ('/dump.sql', 'HIGH'),
            ('/phpinfo.php', 'HIGH'), ('/info.php', 'HIGH'),
            ('/.htaccess', 'MEDIUM'), ('/web.config', 'MEDIUM'),
            ('/robots.txt', 'INFO'), ('/sitemap.xml', 'INFO'),
            ('/admin/', 'INFO'), ('/wp-login.php', 'INFO'),
            ('/swagger-ui.html', 'INFO'), ('/api-docs/', 'INFO'),
            ('/Dockerfile', 'LOW'), ('/docker-compose.yml', 'LOW'),
            ('/.well-known/security.txt', 'INFO'),
        ]

        def check(path, sev):
            try:
                url = urljoin(self.core.target_url, path)
                r = self.get(url, allow_redirects=False)
                if r.status_code == 200 and len(r.content) > 0:
                    text = r.text.lower()[:300]
                    if 'not found' not in text or len(r.content) > 200:
                        ev = f"GET {url}\nStatus: {r.status_code}\nSize: {len(r.content)} bytes\nFirst 200 chars:\n{r.text[:200]}"
                        ftype = 'confirmed' if sev == 'CRITICAL' else 'misconfig'
                        self.add(f'Sensitive File Exposed: {path}', sev, f'File accessible at {url}', f'Remove or restrict {path}', ev, 100, 'A01:2021', 'CWE-552', 'Sensitive Files', ftype)
            except:
                pass

        with ThreadPoolExecutor(max_workers=self.core.threads) as ex:
            list(ex.map(lambda x: check(x[0], x[1]), paths))
