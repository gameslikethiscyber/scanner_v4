import ipaddress
import socket
from urllib.parse import urlparse


def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False

        try:
            addrs = socket.getaddrinfo(hostname, None)
        except (socket.gaierror, OSError):
            return False

        for addr in addrs:
            ip_str = addr[4][0]

            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            if ip.is_loopback:
                return False

            if ip.is_private:
                return False

            if ip.is_link_local:
                return False

            if ip.is_multicast:
                return False

            if ip.is_reserved:
                return False

            if isinstance(ip, ipaddress.IPv4Address):
                if ip in ipaddress.IPv4Network("0.0.0.0/8"):
                    return False

        return True
    except Exception:
        return False
