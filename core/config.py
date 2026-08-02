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

    # Advanced smart crawling (SOP v4.0 Phase 2)
    max_depth: Optional[int] = 10              # None = unlimited
    max_crawl_requests: int = 0                # 0 = unlimited
    max_crawl_duration: float = 0.0            # seconds; 0 = unlimited
    crawl_strategy: str = "breadth"            # breadth | depth
    crawl_scope: str = "domain"                # domain | subdomain | path | all
    include_subdomains: bool = False
    crawl_include_patterns: List[str] = field(default_factory=list)
    crawl_exclude_patterns: List[str] = field(default_factory=list)
    respect_robots: bool = False
    parse_sitemap: bool = True

    # JavaScript crawling (requires Playwright)
    use_js_crawler: bool = True
    js_wait_seconds: int = 5
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

    # Authentication awareness (optional; public scans behave exactly as before)
    auth_detection: bool = True
    auth_prompt: bool = True

    # Optional authentication (SOP v4.0 Phase 1). Anonymous is the default:
    # when `auth_enabled` is False (or an auth spec is absent) no session is
    # attached, no session validation runs, and behaviour is unchanged.
    auth_enabled: bool = False
    auth_type: str = "cookies"            # cookies | bearer | jwt | headers
    auth_cookie_file: str = ""
    auth_cookie_string: str = ""
    auth_token_file: str = ""
    auth_token: str = ""
    auth_headers: list = field(default_factory=list)   # ["Name: Value", ...]
    auth_validate_session: bool = True

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
