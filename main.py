#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Security Scanner v4.0 - Modular Professional Scanner
"""

import sys
import time
import json
from datetime import datetime
from urllib.parse import urlparse

from core.scanner import ScannerCore
from core.reporter import Reporter
from core.fingerprinter import Fingerprinter
from core.classifier import Classifier
from scanners.headers import HeaderScanner
from scanners.tls import TLSScanner
from scanners.cookies import CookieScanner
from scanners.sensitive_files import SensitiveFileScanner
from scanners.sqli import SQLiScanner
from scanners.xss import XSSScanner
from scanners.cors import CORSScanner
from scanners.csrf import CSRFScanner
from scanners.lfi import LFIScanner
from scanners.ssrf import SSRFScanner
from scanners.http_methods import MethodScanner
from scanners.open_redirect import OpenRedirectScanner
from scanners.host_header import HostHeaderScanner
from scanners.source_leaks import SourceLeakScanner
from scanners.dns_scanner import DNSScanner
from scanners.ports import PortScanner
from scanners.security_txt import SecurityTxtScanner
from scanners.tech_detect import TechDetector

class C:
    BOLD = '\033[1m'; RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; CYAN = '\033[96m'; END = '\033[0m'

def banner(target):
    print(f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║           Web Security Scanner v4.0 - Modular Professional                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Target: {target:<69}║
╚══════════════════════════════════════════════════════════════════════════════╝
{C.END}
""")

def main():
    target = input("Enter target URL: ").strip()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    confirm = input(f"Scan {target}? (yes/no): ").strip().lower()
    if confirm not in ['yes', 'y']:
        print("Cancelled."); sys.exit(0)

    threads = input("Threads (default 15): ").strip()
    threads = int(threads) if threads.isdigit() else 15

    banner(target)
    start = time.time()

    core = ScannerCore(target, threads)

    # Phase 1: Fingerprinting
    print(f"{C.BOLD}[*] Phase 1: Technology Fingerprinting...{C.END}")
    fp = Fingerprinter(core)
    tech = fp.detect()
    print(f"   {C.GREEN}Detected: {', '.join(tech) if tech else 'Unknown'}{C.END}\n")

    # Phase 2: Scanning
    print(f"{C.BOLD}[*] Phase 2: Running Security Scans...{C.END}\n")

    scanners = [
        HeaderScanner(core),
        TLSScanner(core),
        CookieScanner(core),
        SensitiveFileScanner(core),
        SQLiScanner(core),
        XSSScanner(core),
        CORSScanner(core),
        CSRFScanner(core),
        LFIScanner(core),
        SSRFScanner(core),
        MethodScanner(core),
        OpenRedirectScanner(core),
        HostHeaderScanner(core),
        SourceLeakScanner(core),
        DNSScanner(core),
        PortScanner(core),
        SecurityTxtScanner(core),
        TechDetector(core),
    ]

    for scanner in scanners:
        scanner.scan()

    # Phase 3: Classification & Reporting
    print(f"\n{C.BOLD}[*] Phase 3: Generating Reports...{C.END}\n")

    classifier = Classifier(core.findings)
    classified = classifier.classify()

    reporter = Reporter(core.target_url, classified, start)
    reporter.print_console()
    reporter.generate_json()
    reporter.generate_html()

    elapsed = time.time() - start
    print(f"\n{C.GREEN}Scan completed in {elapsed:.1f}s{C.END}")

if __name__ == '__main__':
    main()
