import ssl
import socket
import datetime
import requests
import logging
from core.finding import Finding, Status, Severity
from scanners.base import BaseScanner

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger('SeaScanner.TLS')

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
                    self._evidence_builder.verified("Port 443 is closed", payload=None)
                )
                finding.status = Status.PASS
                return finding

            try:
                context = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        tls_version = ssock.version()
                        finding.add_evidence(
                            self._evidence_builder.verified(
                                f"TLS Handshake successful: {tls_version}",
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
                                            f"RSA {key_size}-bit key (strong)", payload=None
                                        )
                                    )
                                else:
                                    finding.add_evidence(
                                        self._evidence_builder.likely(
                                            f"RSA {key_size}-bit key (weak, minimum 2048)", payload=None
                                        )
                                    )

                            finding.fingerprint['certificate'] = {
                                'issuer': str(cert.issuer),
                                'subject': str(cert.subject),
                                'days_left': days_left,
                                'key_size': getattr(pub_key, 'key_size', 0),
                            }

                        cipher = ssock.cipher()
                        if cipher:
                            cipher_name = cipher[0]
                            finding.add_evidence(
                                self._evidence_builder.verified(f"Cipher suite: {cipher_name}", payload=None)
                            )
                            if 'ECDHE' in cipher_name or 'DHE' in cipher_name:
                                finding.add_evidence(
                                    self._evidence_builder.verified("Forward Secrecy supported", payload=None)
                                )
                            else:
                                finding.add_evidence(
                                    self._evidence_builder.likely(
                                        "No forward secrecy (consider ECDHE/DHE ciphers)", payload=None
                                    )
                                )

                        hsts_checked = False
                        for check_url in [f"https://{host}", self.target]:
                            try:
                                hsts_resp = requests.get(check_url, timeout=5)
                                if 'Strict-Transport-Security' in hsts_resp.headers:
                                    hsts_val = hsts_resp.headers['Strict-Transport-Security']
                                    finding.add_evidence(
                                        self._evidence_builder.verified(
                                            f"HSTS: {hsts_val[:60]}", payload=None
                                        )
                                    )
                                else:
                                    finding.add_evidence(
                                        self._evidence_builder.likely("HSTS header missing", payload=None)
                                    )
                                hsts_checked = True
                                break
                            except Exception:
                                continue

                        if not hsts_checked:
                            finding.add_evidence(
                                self._evidence_builder.unknown("Could not check HSTS", payload=None)
                            )

                        compression = getattr(ssock, 'compression', None)
                        if compression and compression != '':
                            finding.add_evidence(
                                self._evidence_builder.possible(
                                    "TLS compression enabled (CRIME attack risk)", payload=None
                                )
                            )
                        else:
                            finding.add_evidence(
                                self._evidence_builder.verified("TLS compression disabled", payload=None)
                            )

                        finding.tests_performed = len(finding.evidence)
                        finding.tests_run = finding.tests_performed
                        from core.evidence import EvidenceLevel
                        likely_or_worse = [e for e in finding.evidence if getattr(e, 'level', None) in (
                            EvidenceLevel.LIKELY, EvidenceLevel.POSSIBLE, EvidenceLevel.CONFIRMED
                        )]
                        finding.tests_passed = finding.tests_run - len(likely_or_worse)
                        finding.status = Status.PASS if finding.tests_passed == finding.tests_run else Status.WARNING

            except Exception as e:
                finding.add_evidence(
                    self._evidence_builder.confirmed(f"TLS Handshake failed: {str(e)}", payload=None)
                )
                finding.status = Status.FAIL
                finding.scan_errors += 1

        except Exception as e:
            finding.add_evidence(
                self._evidence_builder.unknown(f"Scan error: {str(e)}", payload=None)
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
