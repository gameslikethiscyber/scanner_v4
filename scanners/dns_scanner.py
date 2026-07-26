from scanners.base import BaseScanner
import dns.resolver

class DNSScanner(BaseScanner):
    def scan(self):
        print("   [+] DNS Records")

        try:
            answers = dns.resolver.resolve(self.core.hostname, 'TXT')
            spf = any('v=spf1' in str(r) for r in answers)
            if not spf:
                ev = f"Query: TXT {self.core.hostname}\nResult: NO SPF"
                self.add('Missing SPF Record', 'MEDIUM', 'No SPF found', 'Add SPF TXT record', ev, 100, 'A05:2021', 'CWE-291', 'DNS', 'misconfig')
        except:
            ev = f"Query: TXT {self.core.hostname}\nResult: NXDOMAIN"
            self.add('Missing SPF Record', 'MEDIUM', 'No SPF', 'Add SPF', ev, 100, 'A05:2021', 'CWE-291', 'DNS', 'misconfig')

        try:
            answers = dns.resolver.resolve(f'_dmarc.{self.core.hostname}', 'TXT')
            dmarc = any('v=DMARC1' in str(r) for r in answers)
            if not dmarc:
                ev = f"Query: _dmarc.{self.core.hostname}\nResult: NO DMARC"
                self.add('Missing DMARC Record', 'MEDIUM', 'No DMARC', 'Add DMARC', ev, 100, 'A05:2021', 'CWE-291', 'DNS', 'misconfig')
        except:
            ev = f"Query: _dmarc.{self.core.hostname}\nResult: NXDOMAIN"
            self.add('Missing DMARC Record', 'MEDIUM', 'No DMARC', 'Add DMARC', ev, 100, 'A05:2021', 'CWE-291', 'DNS', 'misconfig')
