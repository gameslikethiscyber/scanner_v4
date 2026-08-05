import ipaddress
import socket
import logging
from urllib.parse import urlparse

logger = logging.getLogger("SeaScanner.SSRFGuard")


class SSRFProtection:
    BLOCKED_NETWORKS = [
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fc00::/7'),
    ]

    BLOCKED_HOSTNAMES = [
        'localhost',
        'metadata.google.internal',
        'metadata.goog',
        '169.254.169.254',
    ]

    @classmethod
    def is_safe_url(cls, url: str):
        """Returns (is_safe, reason)"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname

            if not hostname:
                return False, "No hostname found"

            if hostname.lower() in cls.BLOCKED_HOSTNAMES:
                return False, f"Blocked hostname: {hostname}"

            try:
                addrs = socket.getaddrinfo(hostname, None)
            except (socket.gaierror, OSError):
                return False, f"Cannot resolve hostname: {hostname}"

            for addr in addrs:
                ip_str = addr[4][0]
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue

                for network in cls.BLOCKED_NETWORKS:
                    if ip_obj in network:
                        return False, f"Blocked IP range: {ip_str} ({network})"

                if isinstance(ip_obj, ipaddress.IPv4Address):
                    if ip_obj in ipaddress.IPv4Network("0.0.0.0/8"):
                        return False, f"Blocked IP range: {ip_str} (0.0.0.0/8)"

            return True, "Safe"

        except Exception as e:
            return False, f"Validation error: {str(e)}"


# Backward-compatible wrapper
def is_safe_url(url: str) -> bool:
    safe, _reason = SSRFProtection.is_safe_url(url)
    return safe