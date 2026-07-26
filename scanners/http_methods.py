from scanners.base import BaseScanner
from urllib.parse import urljoin

class MethodScanner(BaseScanner):
    def scan(self):
        print("   [+] HTTP Methods")
        for method in ['PUT', 'DELETE', 'TRACE', 'CONNECT']:
            try:
                r = self.core.request(method, self.core.target_url)
                if r.status_code in [405, 403, 501, 400]:
                    continue

                if method == 'PUT':
                    test_url = urljoin(self.core.target_url, '/test-put.txt')
                    try:
                        pr = self.core.request('PUT', test_url, data='TEST')
                        if pr.status_code in [200, 201, 204]:
                            gr = self.get(test_url)
                            if gr.status_code == 200 and 'TEST' in gr.text:
                                ev = f"PUT {test_url}\nStatus: {pr.status_code}\nContent Verified: YES"
                                self.add('PUT Creates Files (Verified)', 'CRITICAL', 'PUT allows file creation', 'Disable PUT', ev, 100, 'A01:2021', 'CWE-650', 'HTTP Methods', 'confirmed')
                                continue
                    except:
                        pass
                    ev = f"Method: PUT\nStatus: {r.status_code}"
                    self.add('PUT Method Accepted', 'HIGH', 'Server accepts PUT', 'Disable PUT', ev, 60, 'A01:2021', 'CWE-650', 'HTTP Methods', 'possible')

                elif method == 'TRACE':
                    ev = f"Method: TRACE\nStatus: {r.status_code}"
                    self.add('TRACE Enabled (XST)', 'HIGH', 'TRACE active', 'Disable TRACE', ev, 80, 'A05:2021', 'CWE-693', 'HTTP Methods', 'confirmed')

                elif method == 'DELETE':
                    ev = f"Method: DELETE\nStatus: {r.status_code}"
                    self.add('DELETE Method Enabled', 'HIGH', 'Server accepts DELETE', 'Disable DELETE', ev, 60, 'A01:2021', 'CWE-650', 'HTTP Methods', 'possible')

                elif method == 'CONNECT':
                    ev = f"Method: CONNECT\nStatus: {r.status_code}"
                    self.add('CONNECT Method Enabled', 'HIGH', 'CONNECT active', 'Disable CONNECT', ev, 60, 'A01:2021', 'CWE-650', 'HTTP Methods', 'possible')
            except:
                pass
