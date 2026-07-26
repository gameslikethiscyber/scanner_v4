from scanners.base import BaseScanner
from urllib.parse import urljoin

class CSRFScanner(BaseScanner):
    def scan(self):
        print("   [+] CSRF Protection")
        if not self.core.forms:
            return

        try:
            r = self.get(self.core.target_url)
            has_samesite = False
            cookie_ev = []
            for c in r.cookies:
                ss = c.get_nonstandard_attr('samesite', '').lower()
                cookie_ev.append(f"  {c.name}: SameSite={ss or 'Not Set'}")
                if ss == 'strict':
                    has_samesite = True

            if has_samesite:
                print("      OK SameSite=Strict detected")
                return
        except:
            pass

        for form in self.core.forms:
            if form['method'] == 'POST':
                names = [i['name'].lower() for i in form['inputs']]
                csrf_names = ['csrf', 'token', '_token', 'xsrf', 'nonce']
                has_token = any(any(cs in n for cs in csrf_names) for n in names)

                if not has_token:
                    action = urljoin(self.core.target_url, form['action']) if form['action'] else self.core.target_url
                    inputs = [i['name'] for i in form['inputs'] if i['name']]
                    ev = f"Form: {action}\nMethod: POST\nInputs: {', '.join(inputs) or 'None'}\nCSRF Token: NO\n\nCookies:\n{chr(10).join(cookie_ev) if cookie_ev else '  None'}"
                    self.add('Possible Missing CSRF Protection', 'HIGH', f"POST form lacks token/SameSite", 'Add CSRF tokens or SameSite=Strict', ev, 65, 'A01:2021', 'CWE-352', 'CSRF', 'possible')
