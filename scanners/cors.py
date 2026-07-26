from scanners.base import BaseScanner

class CORSScanner(BaseScanner):
    def scan(self):
        print("   [+] CORS Configuration")
        try:
            r = self.get(self.core.target_url, headers={'Origin': 'https://evil-attacker.com'})
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')
            acam = r.headers.get('Access-Control-Allow-Methods', '')

            ev = f"Request Origin: https://evil-attacker.com\nResponse:\n  ACAO: {acao}\n  ACAC: {acac}\n  ACAM: {acam}"

            if acao == 'https://evil-attacker.com':
                if acac.lower() == 'true':
                    self.add('CORS: Arbitrary Origin + Credentials', 'CRITICAL', 'Any site can make authenticated requests', 'Whitelist origins strictly', ev, 100, 'A05:2021', 'CWE-942', 'CORS', 'confirmed')
                else:
                    self.add('CORS: Arbitrary Origin Reflected', 'HIGH', 'Origin reflected without validation', 'Validate origins', ev, 95, 'A05:2021', 'CWE-942', 'CORS', 'confirmed')
            elif acao == '*':
                self.add('CORS: Wildcard Origin', 'MEDIUM', 'Any site can read responses', 'Use specific origins', ev, 100, 'A05:2021', 'CWE-942', 'CORS', 'misconfig')

            if acam and any(m in acam.upper() for m in ['PUT', 'DELETE', 'PATCH']):
                self.add('CORS: Dangerous Methods', 'MEDIUM', f'Allows: {acam}', 'Restrict to GET, POST, HEAD', ev, 90, 'A05:2021', 'CWE-942', 'CORS', 'misconfig')
        except:
            pass
