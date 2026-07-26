from scanners.base import BaseScanner
import socket
from concurrent.futures import ThreadPoolExecutor

class PortScanner(BaseScanner):
    def scan(self):
        print("   [+] Common Ports")
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]
        open_ports = []

        def check(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((self.core.hostname, port))
                s.close()
                return port if result == 0 else None
            except:
                return None

        with ThreadPoolExecutor(max_workers=15) as ex:
            results = list(ex.map(check, ports))

        open_ports = [p for p in results if p]
        if open_ports:
            ev = f"Host: {self.core.hostname}\nOpen: {', '.join(map(str, open_ports))}"
            self.add('Open Ports Detected', 'INFO', f'Open: {", ".join(map(str, open_ports))}', 'Close unnecessary ports', ev, 100, 'A05:2021', 'CWE-200', 'Network', 'bestpractice')
