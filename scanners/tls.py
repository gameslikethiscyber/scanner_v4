"""
TLS Scanner - v3.3 (يدعم POST)
"""

import ssl
import socket
import datetime
import requests
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

class TLSScanner(BaseScanner):
    def __init__(self, target: str, session=None, post_data: dict = None):
        super().__init__(target, session, post_data)
        self.name = "TLS/SSL Security"
    
    def scan(self) -> Finding:
        finding = Finding()
        finding.module = self.name
        
        try:
            host = self.target.replace('https://', '').replace('http://', '').split('/')[0]
            
            port_open = self._check_port(host, 443)
            if not port_open:
                finding.add_evidence(
                    self._evidence_builder.verified(
                        "Port 443 is closed",
                        payload=None
                    )
                )
                finding.status = Status.PASS
                return finding
            
            try:
                context = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        finding.add_evidence(
                            self._evidence_builder.verified(
                                f"TLS Handshake successful: {ssock.version()}",
                                payload=None
                            )
                        )
                        
                        cert_der = ssock.getpeercert(binary_form=True)
                        if cert_der and CRYPTOGRAPHY_AVAILABLE:
                            cert = x509.load_der_x509_certificate(cert_der, default_backend())

                            try:
                                not_after = cert.not_valid_after_utc
                            except AttributeError:
                                not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
                            days_left = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
                            if days_left > 30:
                                finding.add_evidence(
                                    self._evidence_builder.verified(
                                        f"Certificate valid for {days_left} days",
                                        payload=None
                                    )
                                )
                            elif days_left > 0:
                                finding.add_evidence(
                                    self._evidence_builder.likely(
                                        f"Certificate expires in {days_left} days",
                                        payload=None
                                    )
                                )
                            else:
                                finding.add_evidence(
                                    self._evidence_builder.confirmed(
                                        f"Certificate expired {abs(days_left)} days ago",
                                        payload=None
                                    )
                                )
                            
                            pub_key = cert.public_key()
                            if isinstance(pub_key, rsa.RSAPublicKey):
                                key_size = pub_key.key_size
                                if key_size >= 2048:
                                    finding.add_evidence(
                                        self._evidence_builder.verified(
                                            f"RSA {key_size} bits (good)",
                                            payload=None
                                        )
                                    )
                                else:
                                    finding.add_evidence(
                                        self._evidence_builder.likely(
                                            f"RSA {key_size} bits (weak)",
                                            payload=None
                                        )
                                    )
                        
                        cipher = ssock.cipher()
                        if cipher:
                            cipher_name = cipher[0]
                            finding.add_evidence(
                                self._evidence_builder.verified(
                                    f"Cipher suite: {cipher_name}",
                                    payload=None
                                )
                            )
                            if 'ECDHE' in cipher_name or 'DHE' in cipher_name:
                                finding.add_evidence(
                                    self._evidence_builder.verified(
                                        "Forward Secrecy supported",
                                        payload=None
                                    )
                                )
                            else:
                                finding.add_evidence(
                                    self._evidence_builder.likely(
                                        "Forward Secrecy not clear",
                                        payload=None
                                    )
                                )
                        
                        try:
                            hsts_resp = requests.get(f"https://{host}", timeout=5)
                            if 'Strict-Transport-Security' in hsts_resp.headers:
                                finding.add_evidence(
                                    self._evidence_builder.verified(
                                        "HSTS header present",
                                        payload=None
                                    )
                                )
                            else:
                                finding.add_evidence(
                                    self._evidence_builder.likely(
                                        "HSTS header missing",
                                        payload=None
                                    )
                                )
                        except Exception:
                            finding.add_evidence(
                                self._evidence_builder.unknown(
                                    "Could not check HSTS",
                                    payload=None
                                )
                            )
                        
                        compression = getattr(ssock, 'compression', None)
                        if compression and compression != '':
                            finding.add_evidence(
                                self._evidence_builder.possible(
                                    "Compression potentially enabled (CRIME risk)",
                                    payload=None
                                )
                            )
                        else:
                            finding.add_evidence(
                                self._evidence_builder.verified(
                                    "Compression not detected",
                                    payload=None
                                )
                            )
                        
                        finding.tests_performed = len(finding.evidence)
                        finding.tests_run = finding.tests_performed
                        finding.tests_passed = len([e for e in finding.evidence if getattr(e, 'level', None) != 'possible'])
                        
                        if finding.tests_passed == finding.tests_run:
                            finding.status = Status.PASS
                        else:
                            finding.status = Status.WARNING
                        
            except Exception as e:
                finding.add_evidence(
                    self._evidence_builder.confirmed(
                        f"TLS Handshake failed: {str(e)}",
                        payload=None
                    )
                )
                finding.status = Status.FAIL
                finding.scan_errors += 1
                
        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.unknown(
                    f"Scan error: {str(e)}",
                    payload=None
                )
            )
            finding.status = Status.UNKNOWN
            finding.scan_errors += 1
        
        return finding
    
    def _check_port(self, host: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.timeout, OSError):
            return False