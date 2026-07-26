class BaseScanner:
    def __init__(self, core):
        self.core = core

    def add(self, title, sev, desc, fix, evidence, conf, owasp, cwe, cat, ftype):
        self.core.add_finding(title, sev, desc, fix, evidence, conf, owasp, cwe, cat, ftype)

    def get(self, url, **kwargs):
        return self.core.get(url, **kwargs)

    def scan(self):
        raise NotImplementedError
