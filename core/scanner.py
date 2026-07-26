import requests
import urllib3
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ScannerCore:
    def __init__(self, target_url, threads=15, timeout=12):
        self.target_url = target_url.rstrip('/')
        self.parsed = urlparse(self.target_url)
        self.domain = self.parsed.netloc
        self.hostname = self.domain.split(':')[0]
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        self.findings = []
        self.forms = []
        self.base_response = None
        self.tech_stack = []

    def get(self, url, **kwargs):
        return self.session.get(url, timeout=self.timeout, verify=False, **kwargs)

    def post(self, url, **kwargs):
        return self.session.post(url, timeout=self.timeout, verify=False, **kwargs)

    def request(self, method, url, **kwargs):
        return self.session.request(method, url, timeout=self.timeout, verify=False, **kwargs)

    def add_finding(self, title, severity, description, remediation, evidence, confidence_pct, owasp, cwe, category, finding_type):
        self.findings.append({
            'title': title, 'severity': severity.upper(), 'description': description,
            'remediation': remediation, 'evidence': evidence, 'confidence': confidence_pct,
            'owasp': owasp, 'cwe': cwe, 'category': category, 'type': finding_type
        })
