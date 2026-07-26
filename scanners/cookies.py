from scanners.base import BaseScanner

class CookieScanner(BaseScanner):
    def scan(self):
        print("   [+] Cookie Security")
        try:
            r = self.get(self.core.target_url)
            if not r.cookies:
                return
            for c in r.cookies:
                issues = []
                if not c.secure: issues.append("No Secure")
                if not c.has_nonstandard_attr('HttpOnly'): issues.append("No HttpOnly")
                ss = c.get_nonstandard_attr('samesite', '').lower()
                if not ss: issues.append("No SameSite")
                elif ss not in ['strict', 'lax']: issues.append(f"Weak SameSite={ss}")

                if issues:
                    ev = f"Cookie: {c.name}\nSecure: {c.secure}\nHttpOnly: {c.has_nonstandard_attr('HttpOnly')}\nSameSite: {ss or 'Not Set'}"
                    self.add(f'Insecure Cookie: {c.name}', 'MEDIUM', f"Lacks: {', '.join(issues)}", 'Set Secure; HttpOnly; SameSite=Strict', ev, 100, 'A05:2021', 'CWE-1004', 'Cookie Security', 'misconfig')
        except:
            pass
