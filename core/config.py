"""
Centralised configuration for the scanner.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict


@dataclass
class ScanConfig:
    # Crawling
    max_pages: int = 30
    crawl_timeout: int = 5

    # JavaScript crawling (requires Playwright)
    use_js_crawler: bool = False
    js_wait_seconds: int = 3
    js_headless: bool = True
    js_max_contexts: int = 3

    # Parallelism
    max_workers: int = 5

    # HTTP request defaults
    request_timeout: int = 10
    long_request_timeout: int = 15

    # User-Agent
    user_agent: str = "SeaScanner/1.0"

    # Authentication
    cookies: List[Dict[str, str]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)

    # Report branding
    company_name: str = "SEA Corporate"
    consultant_name: str = ""
    client_name: str = ""
    report_id: str = ""
    logo_url: str = ""

    def get_branding(self) -> dict:
        return {
            'company_name': self.company_name,
            'consultant_name': self.consultant_name,
            'client_name': self.client_name,
            'report_id': self.report_id,
            'logo_url': self.logo_url,
        }
