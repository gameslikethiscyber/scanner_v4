import json
import time
from datetime import datetime

class C:
    BOLD='\033[1m'; RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
    BLUE='\033[94m'; CYAN='\033[96m'; END='\033[0m'

class Reporter:
    def __init__(self, target, classified, start_time):
        self.target = target
        self.classified = classified
        self.start_time = start_time
        self.hostname = target.split('/')[2].replace(':', '_')

    def print_console(self):
        print(f"\n{C.BOLD}{'='*85}{C.END}")
        print(f"{C.BOLD}                         SCAN RESULTS BY CATEGORY{C.END}")
        print(f"{C.BOLD}{'='*85}{C.END}\n")

        cats = [
            ('confirmed', '🔴 CONFIRMED VULNERABILITIES', C.RED),
            ('possible', '🟠 POSSIBLE VULNERABILITIES', C.YELLOW),
            ('misconfig', '🟡 SECURITY MISCONFIGURATIONS', C.YELLOW),
            ('bestpractice', '🔵 BEST PRACTICES', C.BLUE),
        ]

        for key, label, color in cats:
            findings = self.classified.get(key, [])
            if not findings:
                continue
            print(f"\n{color}{C.BOLD}{label} ({len(findings)}){C.END}")
            print(f"{'─'*85}")
            for f in findings:
                conf_color = C.GREEN if f['confidence'] >= 80 else C.YELLOW if f['confidence'] >= 50 else C.RED
                print(f"  [{f['severity']}] {f['title']}")
                print(f"     Confidence: {conf_color}{f['confidence']}%{C.END} | OWASP: {f['owasp']} | CWE: {f['cwe']}")
                print(f"     {C.CYAN}Reason:{C.END} {f['description'][:80]}")
                print(f"     {C.GREEN}Fix:{C.END} {f['remediation'][:80]}")
                print()

        total = sum(len(v) for v in self.classified.values())
        score = self._calc_score()
        print(f"{C.BOLD}{'='*85}{C.END}")
        print(f"   Total: {total} findings | Security Score: {score}/100")
        print(f"{C.BOLD}{'='*85}{C.END}\n")

    def _calc_score(self):
        c = self.classified
        score = 100
        score -= len(c.get('confirmed', [])) * 20
        score -= len(c.get('possible', [])) * 10
        score -= len(c.get('misconfig', [])) * 5
        return max(0, score)

    def generate_json(self):
        filename = f"report_{self.hostname}_{int(time.time())}.json"
        data = {
            'scan_info': {'target': self.target, 'date': datetime.now().isoformat(),
                         'duration': round(time.time()-self.start_time, 2), 'score': self._calc_score()},
            'results': self.classified
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"📄 JSON: {filename}")
        return filename

    def generate_html(self):
        filename = f"report_{self.hostname}_{int(time.time())}.html"
        score = self._calc_score()
        color = 'green' if score >= 80 else 'orange' if score >= 50 else 'red'

        html = f"""<!DOCTYPE html><html dir="rtl" lang="ar"><head><meta charset="UTF-8">
<title>Security Report</title>
<style>body{{font-family:Segoe UI,Arial;margin:0;padding:20px;background:#f5f5f5;}}
.container{{max-width:1400px;margin:auto;background:white;padding:30px;border-radius:10px;}}
.score{{text-align:center;font-size:48px;font-weight:bold;color:{color};margin:20px;}}
.category{{margin:20px 0;padding:15px;border-radius:8px;}}
.confirmed{{background:#f8d7da;border-left:5px solid #dc3545;}}
.possible{{background:#fff3cd;border-left:5px solid #fd7e14;}}
.misconfig{{background:#fff3cd;border-left:5px solid #ffc107;}}
.bestpractice{{background:#d1ecf1;border-left:5px solid #17a2b8;}}
.finding{{padding:10px;margin:8px 0;background:white;border-radius:5px;}}
.confidence{{display:inline-block;padding:3px 10px;border-radius:12px;font-size:12px;}}
.high-conf{{background:#28a745;color:white;}}
.med-conf{{background:#ffc107;color:black;}}
.low-conf{{background:#dc3545;color:white;}}
.evidence{{background:#f8f9fa;padding:8px;border-radius:4px;font-family:monospace;font-size:11px;white-space:pre-wrap;margin-top:8px;}}
.tags{{margin-top:5px;}} .tag{{background:#e9ecef;padding:2px 8px;border-radius:3px;font-size:10px;margin-right:5px;}}
</style></head><body><div class="container">
<h1>🔒 تقرير فحص أمان الموقع</h1><h2>{self.target}</h2>
<div class="score">{score}/100</div>"""

        cat_names = {'confirmed': ('confirmed', '🔴 ثغرات مؤكدة'), 'possible': ('possible', '🟠 ثغرات محتملة'),
                     'misconfig': ('misconfig', '🟡 إعدادات خاطئة'), 'bestpractice': ('bestpractice', '🔵 أفضل الممارسات')}

        for key, (css_class, title) in cat_names.items():
            findings = self.classified.get(key, [])
            if not findings:
                continue
            html += f'<div class="category {css_class}"><h3>{title} ({len(findings)})</h3>'
            for f in findings:
                conf_class = 'high-conf' if f['confidence'] >= 80 else 'med-conf' if f['confidence'] >= 50 else 'low-conf'
                ev = f['evidence'].replace('<', '&lt;').replace('>', '&gt;')
                html += f"""<div class="finding">
<strong>[{f['severity']}] {f['title']}</strong>
<span class="confidence {conf_class}">Confidence: {f['confidence']}%</span>
<div>{f['description']}</div>
<div class="evidence">{ev}</div>
<div class="tags"><span class="tag">{f['owasp']}</span><span class="tag">{f['cwe']}</span><span class="tag">{f['category']}</span></div>
<div style="background:#d4edda;padding:8px;border-radius:4px;margin-top:5px;"><strong>Fix:</strong> {f['remediation']}</div>
</div>"""
            html += '</div>'

        html += '</div></body></html>'

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"🌐 HTML: {filename}")
        return filename
