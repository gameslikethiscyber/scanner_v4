from scanners.base import BaseScanner
from urllib.parse import quote

class XSSScanner(BaseScanner):
    def scan(self):
        print("   [+] XSS - Context-Aware")

        def check_context(html, payload):
            idx = html.find(payload)
            if idx == -1: return None
            before = html[max(0, idx-20):idx]
            if '&lt;' in before or '&gt;' in before or '&quot;' in before or '&#x' in before:
                return 'encoded'
            script_open = html.rfind('<script', 0, idx)
            script_close = html.find('</script>', idx)
            if script_open != -1 and script_close != -1 and script_open < idx < script_close:
                return 'script'
            tag_open = html.rfind('<', 0, idx)
            tag_close = html.find('>', idx)
            if tag_open != -1 and tag_close != -1:
                between = html[tag_open:tag_close]
                if '=' in between and ('"' in between or "'" in between):
                    return 'attribute'
            if tag_open != -1 and tag_close != -1 and tag_open < idx < tag_close:
                return 'tag'
            return 'body'

        payloads = [
            ('<script>alert(1)</script>', 'script tag'),
            ('"><img src=x onerror=alert(1)>', 'attribute breakout'),
            ("'><svg onload=alert(1)>", 'attribute breakout'),
        ]
        params = ['q', 's', 'search', 'id', 'page', 'cat', 'name', 'user']
        found = False

        for p in params:
            for payload, desc in payloads:
                try:
                    url = f"{self.core.target_url}/?{p}={quote(payload)}"
                    r = self.get(url)
                    ctx = check_context(r.text, payload)
                    if ctx and ctx != 'encoded':
                        ev = f"Parameter: {p}\nPayload: {payload}\nContext: {ctx}\nURL: {url}\nHTML Encoded: NO"
                        conf = 85 if ctx in ['script', 'attribute'] else 70
                        self.add(f'Possible Reflected XSS ({ctx}): {p}', 'HIGH',
                            f"Input reflected in {ctx} context. Type: {desc}", 'Use context-aware encoding', ev, conf, 'A03:2021', 'CWE-79', 'Cross-Site Scripting', 'possible')
                        found = True
                        break
                except:
                    pass
            if found: break

        if not found:
            print("      OK No XSS detected")
