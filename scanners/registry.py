"""
Scanner Registry — centralises all scanner imports and classification.
Adding a new scanner requires only one import + one list entry here.
"""

from typing import Dict, Type
from scanners.base import BaseScanner

# Page-level scanners (run once per crawled page)
from scanners.sqli import SQLiScanner
from scanners.xss import XSSScanner
from scanners.cookies import CookiesScanner
from scanners.sensitive_files import SensitiveFilesScanner
from scanners.cors import CORSScanner
from scanners.csrf import CSRFScanner
from scanners.lfi import LFIScanner
from scanners.ssrf import SSRFScanner
from scanners.http_methods import HTTPMethodsScanner
from scanners.open_redirect import OpenRedirectScanner
from scanners.host_header import HostHeaderScanner
from scanners.source_leaks import SourceLeaksScanner
from scanners.ssti import SSTIScanner

# Host-level scanners (run once per target host)
from scanners.headers import HeadersScanner
from scanners.tls import TLSScanner
from scanners.dns_scanner import DNSScanner
from scanners.ports import PortsScanner
from scanners.security_txt import SecurityTxtScanner
from scanners.tech_detect import TechDetectScanner

PAGE_LEVEL_SCANNERS = [
    SQLiScanner,
    XSSScanner,
    CookiesScanner,
    CORSScanner,
    CSRFScanner,
    LFIScanner,
    SSRFScanner,
    HTTPMethodsScanner,
    OpenRedirectScanner,
    HostHeaderScanner,
    SourceLeaksScanner,
    SSTIScanner,
]

HOST_LEVEL_SCANNERS = [
    HeadersScanner,
    TLSScanner,
    DNSScanner,
    PortsScanner,
    SecurityTxtScanner,
    TechDetectScanner,
    SensitiveFilesScanner,
]

ALL_SCANNERS = PAGE_LEVEL_SCANNERS + HOST_LEVEL_SCANNERS

_SCANNER_NAME_MAP = {
    'SQL Injection': SQLiScanner,
    'XSS Detection': XSSScanner,
    'Cookies Security': CookiesScanner,
    'CORS Configuration': CORSScanner,
    'CSRF Protection': CSRFScanner,
    'LFI Detection': LFIScanner,
    'SSRF Detection': SSRFScanner,
    'HTTP Methods': HTTPMethodsScanner,
    'Open Redirect': OpenRedirectScanner,
    'Host Header Injection': HostHeaderScanner,
    'Source Code Leaks': SourceLeaksScanner,
    'Headers Security': HeadersScanner,
    'TLS/SSL Security': TLSScanner,
    'DNS Security': DNSScanner,
    'Open Ports': PortsScanner,
    'Security.txt': SecurityTxtScanner,
    'Technology Detection': TechDetectScanner,
    'Sensitive Files': SensitiveFilesScanner,
    'SSTI Detection': SSTIScanner,
}

def get_scanner_by_name(name: str):
    return _SCANNER_NAME_MAP.get(name)

def is_host_level(scanner_class: Type[BaseScanner]) -> bool:
    return scanner_class in HOST_LEVEL_SCANNERS

def is_page_level(scanner_class: Type[BaseScanner]) -> bool:
    return scanner_class in PAGE_LEVEL_SCANNERS
