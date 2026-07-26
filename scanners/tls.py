import socket, ssl
from scanners.base import BaseScanner

class TLSScanner(BaseScanner):
    def scan(self):
        print("   [+] SSL/TLS Certificate")
        if not self.core.target_url.startswith('https'):
            ev = f"URL: {self.core.target_url}\nProtocol: HTTP only"
            self.add('No HTTPS Encryption', 'CRITICAL', 'Site uses HTTP - traffic is plaintext', 'Enable HTTPS immediately', ev, 100, 'A02:2021', 'CWE-319', 'Cryptographic Failures', 'misconfig')
            return
        try:
            port = int(self.core.domain.split(':')[1]) if ':' in self.core.domain else 443
            ctx = ssl.create_default_context()
            with socket.create_connection((self.core.hostname, port), timeout=self.core.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=self.core.hostname) as ss:
                    cert = ss.getpeercert()
                    ver = ss.version()
                    cipher = ss.cipher()

                    if ver in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        ev = f"TLS: {ver}\nCipher: {cipher[0] if cipher else 'N/A'}"
                        self.add(f'Weak TLS: {ver}', 'HIGH', f'Deprecated protocol {ver}', 'Disable TLS 1.0/1.1', ev, 100, 'A02:2021', 'CWE-326', 'Cryptographic Failures', 'misconfig')

                    if cipher and any(w in cipher[0] for w in ['RC4', 'DES', '3DES', 'MD5', 'NULL']):
                        ev = f"Cipher: {cipher[0]}"
                        self.add(f'Weak Cipher: {cipher[0]}', 'HIGH', 'Weak encryption', 'Use strong ciphers only', ev, 100, 'A02:2021', 'CWE-326', 'Cryptographic Failures', 'misconfig')

                    if cert.get('notAfter'):
                        exp = ssl.cert_time_to_seconds(cert['notAfter'])
                        days = (exp - __import__('time').time()) / 86400
                        if days < 30:
                            ev = f"Expires: {cert['notAfter']}\nDays left: {int(days)}"
                            self.add('Certificate Expiring Soon', 'HIGH', f'Expires in {int(days)} days', 'Renew now', ev, 100, 'A02:2021', 'CWE-298', 'Cryptographic Failures', 'misconfig')
        except Exception as e:
            pass
