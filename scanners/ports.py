import socket
import concurrent.futures
import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

logger = logging.getLogger('SeaScanner.Ports')

class PortsScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "Open Ports"
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
        }
        self.sensitive_ports = [21, 23, 25, 110, 143, 445, 3306, 3389, 5432, 6379, 27017]

    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name

        try:
            host = self.target.replace('https://', '').replace('http://', '').split('/')[0]
            open_ports = []

            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(self._check_port, host, port): port for port in self.common_ports}
                for future in concurrent.futures.as_completed(futures):
                    port = futures[future]
                    try:
                        if future.result(timeout=3):
                            open_ports.append(port)
                    except Exception:
                        continue

            if open_ports:
                open_details = [f"{p}({self.common_ports[p]})" for p in sorted(open_ports)]
                finding.add_evidence(
                    self._evidence_builder.verified(
                        f"Open ports: {', '.join(open_details)}",
                        payload=None
                    )
                )
                finding.fingerprint['open_ports'] = open_details

                sensitive_open = [p for p in open_ports if p in self.sensitive_ports]
                if sensitive_open:
                    sensitive_details = [f"{p}({self.common_ports[p]})" for p in sorted(sensitive_open)]
                    finding.add_evidence(
                        self._evidence_builder.likely(
                            f"Sensitive ports open: {', '.join(sensitive_details)}",
                            payload=None
                        )
                    )
                    finding.confirmations += 1

                finding.tests_performed = len(self.common_ports)
                finding.tests_run = finding.tests_performed
                finding.tests_passed = len(open_ports)
                finding.status = Status.WARNING if sensitive_open else Status.PASS
                if sensitive_open:
                    finding.severity = Severity.MEDIUM
            else:
                finding.add_evidence(
                    self._evidence_builder.verified("No open ports detected", payload=None)
                )
                finding.tests_performed = len(self.common_ports)
                finding.tests_run = finding.tests_performed
                finding.tests_passed = finding.tests_performed
                finding.status = Status.PASS

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.error(f"Error during port scan: {str(e)}", payload=None)
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1

        return finding

    def _check_port(self, host: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.timeout, OSError):
            return False
