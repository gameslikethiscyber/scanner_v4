#!/usr/bin/env python3
"""
SEA CORPORATE Security Scanner v1.0
Professional Security Scanner with Unified Results
"""

import os
import sys
import json
import logging
from datetime import datetime
from urllib.parse import parse_qs, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# محاولة استيراد Rich للواجهة الجميلة
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️ Rich library not found. Install with: pip install rich")
    print()

from core.finding import ScanResult
from core.reporter import Reporter
from core.http_client import TrackedSession
from core.config import ScanConfig
from core.browser import BrowserManager, PLAYWRIGHT_AVAILABLE
from scanners.registry import ALL_SCANNERS, HOST_LEVEL_SCANNERS, PAGE_LEVEL_SCANNERS

log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('SeaScanner')

def validate_post_data(post_input: str) -> dict:
    """Validate and sanitize POST data input"""
    if not post_input:
        return None

    try:
        data = json.loads(post_input)
        if not isinstance(data, dict):
            raise ValueError("POST data must be a JSON object")

        for key, value in data.items():
            if not isinstance(key, str):
                raise ValueError(f"Invalid key type: {type(key)}")
            if len(str(value)) > 10000:
                raise ValueError(f"Value too long for key: {key}")

        return data
    except json.JSONDecodeError:
        pass

    try:
        if '=' not in post_input:
            raise ValueError("Invalid format: must contain key=value pairs")

        parsed = parse_qs(post_input, keep_blank_values=True)

        result = {}
        for key, values in parsed.items():
            if not isinstance(key, str) or not key.strip():
                continue

            clean_key = key.strip()[:256]

            if len(values) == 1:
                clean_value = str(values[0])
            else:
                clean_value = [str(v) for v in values]

            def _too_long(value):
                if isinstance(value, str):
                    return len(value) > 10000
                return any(len(v) > 10000 for v in value)

            if _too_long(clean_value):
                raise ValueError(f"Value too long for key: {clean_key}")

            result[clean_key] = clean_value

        return result if result else None

    except Exception as e:
        raise ValueError(f"Failed to parse POST data: {str(e)}")

if RICH_AVAILABLE:
    console = Console()
else:
    console = None

class SeaScanner:
    def __init__(self, config: ScanConfig = None):
        self.config = config or ScanConfig()
        self.version = "1.0.0"
        self.target = None
        self.post_data = None
        self.scan_result = ScanResult()
        self.pages = []
        self.host_scan_done = False
        self.start_time = None
        self.session = TrackedSession()
        self.session.headers.update({
            'User-Agent': self.config.user_agent
        })
        self.browser_manager = None
        if self.config.use_js_crawler and PLAYWRIGHT_AVAILABLE:
            self.browser_manager = BrowserManager(
                headless=self.config.js_headless,
                max_contexts=self.config.js_max_contexts,
            )
            self.browser_manager.start()
        # Authentication awareness (optional, in-memory, redacted)
        self.auth_detection = None
        self.auth_decision = None
        self.auth_session = None
        self._auth_probe_classifications = []
    
    def show_banner(self):
        if RICH_AVAILABLE and console:
            banner = f"""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║    ███████╗███████╗ █████╗     ██████╗██████╗ ██████╗    ║
║    ██╔════╝██╔════╝██╔══██╗   ██╔════╝██╔══██╗██╔══██╗   ║
║    ███████╗█████╗  ███████║   ██║     ██████╔╝██████╔╝   ║
║    ╚════██║██╔══╝  ██╔══██║   ██║     ██╔══██╗██╔══██╗   ║
║    ███████║███████╗██║  ██║   ╚██████╗██║  ██║██║  ██║   ║
║    ╚══════╝╚══════╝╚═╝  ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ║
║                                                           ║
║         S E A   C O R P O R A T E                        ║
║      Security Scanner v{self.version} - Enterprise        ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
            """
            console.print(Panel(banner, style="bold cyan", border_style="blue"))
            console.print("[dim]Advanced Web Security Scanner - All Rights Reserved[/dim]\n")
        else:
            print("=" * 60)
            print("   SEA CORPORATE Security Scanner v1.0")
            print("=" * 60)
            print()
    
    def _show_playwright_status(self):
        from core.browser import PLAYWRIGHT_AVAILABLE as PW
        if RICH_AVAILABLE and console:
            if PW:
                console.print("[dim]🧪 Playwright detected — JavaScript crawling available[/dim]")
            else:
                console.print("[dim]🧪 Playwright not found — JS crawling unavailable (pip install playwright)[/dim]")
        logger.info("Playwright available: %s", PW)
    
    def _prompt_js_crawler(self):
        from core.browser import PLAYWRIGHT_AVAILABLE as PW
        if not PW:
            self.config.use_js_crawler = False
            return
        if self.config.use_js_crawler:
            return
        if RICH_AVAILABLE and console:
            choice = console.input("[bold yellow]🧪 Enable JavaScript-aware crawling? (y/n, default n): [/bold yellow]").strip().lower()
        else:
            choice = input("🧪 Enable JavaScript-aware crawling? (y/n, default n): ").strip().lower()
        if choice in ('y', 'yes'):
            self.config.use_js_crawler = True
            self.browser_manager = BrowserManager(
                headless=self.config.js_headless,
                max_contexts=self.config.js_max_contexts,
            )
            started = self.browser_manager.start()
            if RICH_AVAILABLE and console:
                if started:
                    console.print("[green]✅ Playwright browser launched successfully[/green]")
                else:
                    console.print("[red]❌ Failed to launch Playwright browser[/red]")
            logger.info("JS crawling enabled via prompt, browser started=%s", started)
        else:
            logger.info("JS crawling declined by user")
    
    def get_target(self):
        if RICH_AVAILABLE and console:
            target = console.input("[bold yellow]🎯 Target URL: [/bold yellow]").strip()
        else:
            target = input("🎯 Target URL: ").strip()
        
        if not target:
            if RICH_AVAILABLE and console:
                console.print("[red]❌ Target cannot be empty![/red]")
            else:
                print("❌ Target cannot be empty!")
            return self.get_target()
        
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return target
    
    def get_host(self) -> str:
        parsed = urlparse(self.target)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    # ---- دوال POST data ----
    def auto_extract_post_data(self):
        try:
            from core.crawler import Crawler
            if RICH_AVAILABLE and console:
                console.print("[dim]🤖 Scanning for POST forms...[/dim]")
            crawler = Crawler(session=self.session)
            forms = crawler.extract_post_forms(self.target)
            if forms:
                if RICH_AVAILABLE and console:
                    console.print(f"[green]✅ Found {len(forms)} POST form(s) automatically![/green]")
                    for i, form in enumerate(forms):
                        console.print(f"  [dim]Form {i+1}: {', '.join(form['fields'].keys())}[/dim]")
                return forms[0]['fields']
            else:
                if RICH_AVAILABLE and console:
                    console.print("[yellow]⚠️ No POST forms found automatically.[/yellow]")
                return None
        except ImportError:
            if RICH_AVAILABLE and console:
                console.print("[yellow]⚠️ Crawler not available. Install beautifulsoup4: pip install beautifulsoup4[/yellow]")
            else:
                print("⚠️ Crawler not available. Install beautifulsoup4: pip install beautifulsoup4")
            return None
        except Exception as e:
            if RICH_AVAILABLE and console:
                console.print(f"[yellow]⚠️ Auto-extraction failed: {e}[/yellow]")
            else:
                print(f"⚠️ Auto-extraction failed: {e}")
            return None
    
    def get_post_data_manual(self):
        if RICH_AVAILABLE and console:
            choice = console.input("\n[bold yellow]📤 Do you want to send POST data manually? (y/n): [/bold yellow]").strip().lower()
        else:
            choice = input("\n📤 Do you want to send POST data manually? (y/n): ").strip().lower()
        
        if choice not in ['y', 'yes']:
            return None
        
        if RICH_AVAILABLE and console:
            console.print("[dim]Enter POST data as JSON or key=value pairs[/dim]")
            post_input = console.input("[bold yellow]📝 POST data: [/bold yellow]").strip()
        else:
            post_input = input("📝 POST data: ").strip()
        
        if not post_input:
            return None
        
        try:
            valid = validate_post_data(post_input)
            if RICH_AVAILABLE and console:
                console.print("[green]✅ POST data validated[/green]")
            return valid
        except ValueError as e:
            if RICH_AVAILABLE and console:
                console.print(f"[red]❌ Invalid POST data: {e}[/red]")
            else:
                print(f"❌ Invalid POST data: {e}")
            return self.get_post_data_manual()
    
    def get_post_data(self):
        if RICH_AVAILABLE and console:
            console.print("\n[bold cyan]📤 POST Data Collection[/bold cyan]")
        
        post_data = self.auto_extract_post_data()
        if post_data:
            if RICH_AVAILABLE and console:
                console.print(f"[dim]Extracted data: {json.dumps(post_data, ensure_ascii=False)}[/dim]")
                choice = console.input("[bold yellow]Use this data? (y/n): [/bold yellow]").strip().lower()
            else:
                print(f"Extracted data: {json.dumps(post_data, ensure_ascii=False)}")
                choice = input("Use this data? (y/n): ").strip().lower()
            if choice in ['y', 'yes']:
                return post_data
        
        if RICH_AVAILABLE and console:
            console.print("[dim]Switching to manual entry...[/dim]")
        return self.get_post_data_manual()
    
    # ---- الزحف ----
    def crawl_target(self):
        try:
            from core.crawler import Crawler
            from core.browser import PLAYWRIGHT_AVAILABLE as PW_AVAIL

            use_js = self.config.use_js_crawler and self.browser_manager and self.browser_manager.is_available

            if RICH_AVAILABLE and console:
                if not self.config.use_js_crawler:
                    console.print("[dim]🧪 JS crawling: disabled (config.use_js_crawler=False)[/dim]")
                elif not PW_AVAIL:
                    console.print("[dim]🧪 JS crawling: Playwright not installed (pip install playwright)[/dim]")
                elif not self.browser_manager or not self.browser_manager.is_available:
                    console.print("[dim]🧪 JS crawling: browser failed to launch (check logs)[/dim]")
                else:
                    console.print("[bold green]🧪 JavaScript-aware crawling: ACTIVE[/bold green]")

            logger.info("Crawler decision: use_js=%s (config=%s, playwright=%s, browser_available=%s)",
                        use_js, self.config.use_js_crawler, PW_AVAIL,
                        self.browser_manager.is_available if self.browser_manager else 'N/A')

            if RICH_AVAILABLE and console:
                console.print("[bold cyan]🕷️ Crawling target...[/bold cyan]")

            crawler = Crawler(
                session=self.session,
                use_js=use_js,
                browser_manager=self.browser_manager,
                scope=self.config.crawl_scope,
                include_subdomains=self.config.include_subdomains,
                include_patterns=self.config.crawl_include_patterns,
                exclude_patterns=self.config.crawl_exclude_patterns,
                max_depth=self.config.max_depth,
                max_requests=self.config.max_crawl_requests,
                max_duration=self.config.max_crawl_duration,
                crawl_strategy=self.config.crawl_strategy,
                respect_robots=self.config.respect_robots,
                parse_sitemap=self.config.parse_sitemap,
                timeout=self.config.crawl_timeout or self.config.request_timeout,
            )
            self.pages = crawler.crawl(
                self.target,
                max_pages=self.config.max_pages,
                js_wait_seconds=self.config.js_wait_seconds,
            )

            pre_filter_count = len(self.pages)

            # Keep pages with params, forms, or JS variables
            self.pages = [p for p in self.pages if p.get('params') or p.get('forms') or p.get('js_variables')]

            # Fallback: if no useful pages found, add base URL as a simple page
            # so page-level scanners (headers, cookies, CORS, tech detect) can still run
            if not self.pages:
                self.pages = [{
                    'url': self.target,
                    'params': {},
                    'forms': [],
                }]
                logger.info("No useful pages found — added base URL as fallback page")

            diag = crawler.diag if hasattr(crawler, 'diag') else {}
            crawl_type = diag.get('crawler_type', 'http')

            # Pipe crawler diagnostics into ScanResult
            sr = self.scan_result
            sr.crawler_type = crawl_type
            sr.urls_discovered = list(crawler.visited) if hasattr(crawler, 'visited') else []
            sr.urls_crawled = diag.get('urls_visited', 0)
            sr.urls_skipped = sum([
                diag.get('urls_skipped_extension', 0),
                diag.get('urls_skipped_content_type', 0),
                diag.get('urls_skipped_status', 0),
                diag.get('urls_skipped_duplicate', 0),
                diag.get('urls_skipped_not_html', 0),
                diag.get('urls_skipped_timeout', 0),
                diag.get('urls_skipped_error', 0),
            ])
            sr.useful_pages = diag.get('pages_useful', 0)
            sr.not_useful_pages = diag.get('pages_not_useful', 0)
            sr.forms_discovered = diag.get('forms_discovered', 0)
            sr.hidden_inputs = diag.get('hidden_inputs_discovered', 0)
            sr.params_discovered = sum(len(p.get('params', {})) for p in self.pages)
            sr.pages_crawled = len(self.pages)

            # Advanced crawl metrics (SOP v4.0 Phase 2): attack surface + stats.
            sr.crawl_duration_s = diag.get('crawl_duration_s', 0.0)
            sr.crawl_duplicates = diag.get('duplicates', 0)
            sr.crawl_redirects = diag.get('redirects', 0)
            sr.crawl_failed = diag.get('failed', 0)
            sr.crawl_sitemap_entries = diag.get('sitemap_entries', 0)
            sr.crawl_robots_entries = diag.get('robots_entries', 0)
            sr.crawl_sitemap_parsed = diag.get('sitemap_parsed', False)
            sr.crawl_robots_parsed = diag.get('robots_parsed', False)
            sr.attack_surface = getattr(crawler, 'attack_surface', None)
            sr.crawl_classifications = (sr.attack_surface or {}).get('classifications', {})

            # Extract technologies from page titles / content
            techs = set()
            for p in self.pages:
                title = p.get('title', '') or ''
                if 'wordpress' in title.lower():
                    techs.add('WordPress')
                if 'drupal' in title.lower():
                    techs.add('Drupal')
                if 'joomla' in title.lower():
                    techs.add('Joomla')
                if 'laravel' in title.lower() or 'lumen' in title.lower():
                    techs.add('Laravel')
            sr.technologies = list(techs)

            # Count cookies from session
            if hasattr(self.session, 'cookies'):
                sr.cookies_found = len(self.session.cookies)

            if RICH_AVAILABLE and console:
                console.print()
                console.print("[bold]📊 Crawl Diagnostics:[/bold]")

                if crawl_type == 'js':
                    console.print(f"  Crawler:          [green]JavaScript (Playwright)[/green]")
                else:
                    console.print(f"  Crawler:          [cyan]HTTP (BeautifulSoup)[/cyan]")

                console.print(f"  URLs visited:     {diag.get('urls_visited', '?')}")
                console.print(f"  Useful pages:     [green]{diag.get('pages_useful', '?')}[/green]")
                console.print(f"  Non-useful pages: [yellow]{diag.get('pages_not_useful', '?')}[/yellow]")
                console.print(f"  Skipped (ext):    {diag.get('urls_skipped_extension', '?')}")
                console.print(f"  Skipped (CT):     {diag.get('urls_skipped_content_type', '?')}")
                console.print(f"  Skipped (HTTP):   {diag.get('urls_skipped_status', '?')}")
                console.print(f"  Skipped (dup):    {diag.get('urls_skipped_duplicate', '?')}")
                console.print(f"  Timeouts:         [red]{diag.get('urls_skipped_timeout', '?')}[/red]")
                console.print(f"  Errors:           [red]{diag.get('urls_skipped_error', '?')}[/red]")

                links_found = diag.get('links_found_total', 0)
                links_int = diag.get('links_internal', 0)
                links_ext = diag.get('links_external', 0)
                links_skip_ext = diag.get('links_skipped_extension', 0)
                links_skip_hash = diag.get('links_skipped_hash', 0)
                links_queued = links_int - links_skip_ext - links_skip_hash
                console.print(f"  Links found:      {links_found}")
                console.print(f"    Internal:       {links_int}")
                console.print(f"    External:       {links_ext}")
                console.print(f"    Skipped (ext):  {links_skip_ext}")
                console.print(f"    Skipped (#):    {links_skip_hash}")
                console.print(f"    Enqueued:       [cyan]{links_queued}[/cyan]")
                console.print(f"  Forms found:      {diag.get('forms_discovered', '?')}")
                console.print(f"  Hidden inputs:    {diag.get('hidden_inputs_discovered', '?')}")
                console.print(f"  Before filter:    [cyan]{pre_filter_count}[/cyan] pages")
                if pre_filter_count == 0 and len(self.pages) == 1:
                    console.print(f"  After filter:     [bold]0[/bold] useful pages")
                    console.print(f"  [yellow]⚠️ No useful pages found — using base URL as fallback[/yellow]")
                else:
                    console.print(f"  After filter:     [bold]{len(self.pages)}[/bold] useful pages")
                console.print()

            logger.info("Crawl stats: type=%s visited=%d useful=%d not_useful=%d skipped_ext=%d skipped_ct=%d skipped_http=%d skipped_dup=%d pre_filter=%d post_filter=%d",
                        crawl_type, diag.get('urls_visited', 0), diag.get('pages_useful', 0),
                        diag.get('pages_not_useful', 0), diag.get('urls_skipped_extension', 0),
                        diag.get('urls_skipped_content_type', 0), diag.get('urls_skipped_status', 0),
                        diag.get('urls_skipped_duplicate', 0), pre_filter_count, len(self.pages))
            
            return True
        except ImportError:
            if RICH_AVAILABLE and console:
                console.print("[yellow]⚠️ Crawler not available. Install beautifulsoup4: pip install beautifulsoup4[/yellow]")
            else:
                print("⚠️ Crawler not available. Install beautifulsoup4: pip install beautifulsoup4")
            self.pages = [{'url': self.target, 'params': {}, 'forms': []}]
            return False
        except Exception as e:
            if RICH_AVAILABLE and console:
                console.print(f"[red]❌ Crawling failed: {e}[/red]")
            else:
                print(f"❌ Crawling failed: {e}")
            import traceback
            traceback.print_exc()
            self.pages = [{'url': self.target, 'params': {}, 'forms': []}]
            return False
    
    def get_scanners(self):
        return ALL_SCANNERS

    def get_host_level_scanners(self):
        return HOST_LEVEL_SCANNERS

    def get_page_level_scanners(self):
        return PAGE_LEVEL_SCANNERS
    
    # ---- فحص المضيف (مرة واحدة) ----
    def run_host_scan(self):
        if self.host_scan_done:
            return
        
        host = self.get_host()
        if RICH_AVAILABLE and console:
            console.print(f"[bold cyan]🏠 Host Scan: {host}[/bold cyan]")
        
        scanners = self.get_host_level_scanners()
        for scanner_class in scanners:
            try:
                scanner = scanner_class(host, session=self.session)
                finding = scanner.run()
                self.scan_result.add_finding(finding)
            except Exception as e:
                if RICH_AVAILABLE and console:
                    console.print(f"[red]   ❌ Error in {scanner_class.__name__}: {e}[/red]")
        
        self.host_scan_done = True
    
    # ---- فحص صفحة واحدة ----
    def run_page_scan(self, page_url, post_data=None):
        scanners = self.get_page_level_scanners()
        
        if RICH_AVAILABLE and console:
            console.print(f"[dim]🔍 Scanning: {page_url}[/dim]")
        logger.info("Page scan: %s", page_url)
        
        for scanner_class in scanners:
            try:
                scanner = scanner_class(page_url, session=self.session, post_data=post_data)
                finding = scanner.run()
                self.scan_result.add_finding(finding)
                logger.info("Scanner %s on %s: %s", scanner_class.__name__, page_url, finding.status.value)
            except Exception as e:
                if RICH_AVAILABLE and console:
                    console.print(f"[red]   ❌ Error in {scanner_class.__name__}: {e}[/red]")
                logger.error("Error in %s on %s: %s", scanner_class.__name__, page_url, str(e))
    
    # ---- فحص جميع الصفحات (متوازي) ----
    def run_scan_on_all_pages(self):
        # Always run host-level scan first (doesn't depend on pages)
        self.run_host_scan()

        if not self.pages:
            if RICH_AVAILABLE and console:
                console.print("[red]❌ No pages to scan![/red]")
            return

        # 2. تشغيل فحص كل صفحة (بالتوازي)
        if RICH_AVAILABLE and console:
            console.print(f"[bold cyan]📄 Scanning {len(self.pages)} pages...[/bold cyan]\n")
        
        # استخدام ThreadPoolExecutor للفحص المتوازي
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = []
            for page in self.pages:
                page_url = page['url']
                params = page.get('params', {})
                forms = page.get('forms', [])
                
                # بناء الرابط مع المعاملات
                if params:
                    from urllib.parse import urlencode
                    qs = urlencode(params, doseq=True)
                    page_url = page_url + ('&' if '?' in page_url else '?') + qs
                
                # استخراج POST data من أول نموذج
                post_data = None
                if forms and forms[0].get('fields'):
                    post_data = forms[0]['fields']
                
                futures.append(executor.submit(self.run_page_scan, page_url, post_data))
            
            # انتظار انتهاء جميع المهام
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error("Page scan thread failed: %s", str(e))
                    if RICH_AVAILABLE and console:
                        console.print(f"[red]❌ Scan error: {e}[/red]")
        
        self.scan_result.end_time = datetime.now()
        self.scan_result.requests_sent = self.session.request_count
        self.scan_result.aggregate_safe_findings()

        # Phase A9: correlation + risk + coverage + assessment are owned by the
        # single assessment pipeline, invoked once from run() via assess().

        if RICH_AVAILABLE and console:
            console.print(f"[green]✅ Scanned {len(self.pages)} pages[/green]")
    
    def show_scan_info(self):
        now = datetime.now().strftime("%H:%M:%S")
        
        if RICH_AVAILABLE and console:
            info_table = Table(box=box.ROUNDED, style="bright_blue")
            info_table.add_column("Property", style="bold cyan")
            info_table.add_column("Value", style="white")
            
            info_table.add_row("🎯 Target", self.target)
            info_table.add_row("⚙️ Engine", "SeaScan Engine v2.0")
            info_table.add_row("⏰ Started", now)
            info_table.add_row("📋 Modules", f"{len(self.get_scanners())} enabled")
            info_table.add_row("📊 Mode", "Deep Scan (Comprehensive)")
            info_table.add_row("📄 Pages Found", str(len(self.pages)))
            if self.post_data:
                info_table.add_row("📤 POST Data", f"Provided ({len(self.post_data)} fields)")
            else:
                info_table.add_row("📤 POST Data", "None")
            
            console.print(Panel(info_table, title="[bold green]⚙️ Scan Configuration[/bold green]", border_style="green"))
            console.print()
        else:
            print(f"📋 Target: {self.target}")
            print(f"⏰ Started: {now}")
            print(f"📄 Pages Found: {len(self.pages)}")
            if self.post_data:
                print(f"📤 POST Data: Provided ({len(self.post_data)} fields)")
            else:
                print("📤 POST Data: None")
            print("=" * 60)
            print()
    
    def show_summary(self):
        stats = self.scan_result.get_statistics()
        skipped_count = len(self.scan_result.get_skipped_findings())
        
        if RICH_AVAILABLE and console:
            summary_table = Table(box=box.DOUBLE_EDGE, style="bright_white")
            summary_table.add_column("📊 Metric", style="bold cyan")
            summary_table.add_column("📈 Value", style="bold yellow")
            
            summary_table.add_row("⏱️ Duration", f"{stats['duration']:.1f} seconds")
            summary_table.add_row("📋 Modules", str(stats['total']))
            summary_table.add_row("📄 Pages", str(len(self.pages)))
            summary_table.add_row("🔴 Vulnerabilities", str(stats['vulnerabilities']))
            summary_table.add_row("✅ Passed", str(stats['safe']))
            summary_table.add_row("⚠️ Warnings", str(stats['warning']))
            summary_table.add_row("ℹ️ Info", str(stats['info']))
            summary_table.add_row("⏭️ Skipped", str(skipped_count))
            summary_table.add_row("🎯 Risk Score", f"{stats['risk_score']}%")
            summary_table.add_row("📊 Overall Severity", stats['overall_severity'])
            summary_table.add_row("📊 Coverage", f"{stats['coverage_percentage']}% ({stats['coverage_executed']}/{stats['coverage_total']})")
            auth_stats = stats.get('auth') or {}
            if auth_stats.get('detected') or auth_stats.get('state', 'none') not in ('none', ''):
                summary_table.add_row("🔐 Authentication", f"{auth_stats.get('method_label', 'N/A')} ({auth_stats.get('state_label', 'N/A')})")

            console.print(Panel(summary_table, title="[bold green]📊 Scan Summary[/bold green]", border_style="green"))
            
            findings_table = Table(box=box.ROUNDED)
            findings_table.add_column("Category", style="bold")
            findings_table.add_column("Count", justify="center")
            findings_table.add_column("Severity", justify="center")
            
            findings_table.add_row("🔴 Critical", str(stats['critical']), "[red]● CRITICAL[/red]")
            findings_table.add_row("🟠 High", str(stats['high']), "[orange]● HIGH[/orange]")
            findings_table.add_row("🟡 Medium", str(stats['medium']), "[yellow]● MEDIUM[/yellow]")
            findings_table.add_row("🟢 Low", str(stats['low']), "[green]● LOW[/green]")
            findings_table.add_row("⚠️ Warnings", str(stats['warning']), "[orange]● WARNING[/orange]")
            findings_table.add_row("ℹ️ Info", str(stats['info']), "[blue]● INFO[/blue]")
            findings_table.add_row("✅ Passed", str(stats['safe']), "[bold green]● PASSED[/bold green]")
            findings_table.add_row("⏭️ Skipped", str(skipped_count), "[orange]● SKIPPED[/orange]")
            
            console.print(Panel(findings_table, title="📋 Findings Breakdown", border_style="blue"))
            
            risk_score = stats.get('risk_score', 0)
            overall_severity = stats.get('overall_severity', '✅ No Risk')
            overall_color = stats.get('overall_color', '#2196F3')
            overall_tier = stats.get('overall_tier', 'none')
            
            if overall_tier == 'critical':
                color = "red"
                icon = "🔥"
            elif overall_tier == 'high':
                color = "orange"
                icon = "🚨"
            elif overall_tier in ('elevated', 'medium'):
                color = "yellow"
                icon = "⚠️"
            elif overall_tier == 'low':
                color = "green"
                icon = "🟡"
            else:
                color = "green"
                icon = "✅"
            
            meter = "█" * int(risk_score / 10) + "░" * (10 - int(risk_score / 10))
            console.print(f"\n[bold]🎯 Risk Meter:[/bold] [{color}]{meter}[/{color}] {risk_score}%")
            console.print(f"[{color}]Status: {icon} {overall_severity}[/{color}]")
            
            if stats.get('overall_description'):
                console.print(f"\n[dim]💡 {stats['overall_description']}[/dim]")
            
            console.print("\n[bold cyan]💡 Recommendations:[/bold cyan]")
            if stats['critical'] > 0:
                console.print("[red]⚠ Critical vulnerabilities found! Immediate action required.[/red]")
            elif stats['high'] > 0:
                console.print("[orange]⚠ High vulnerabilities found. Address them as soon as possible.[/orange]")
            elif stats['vulnerabilities'] > 3:
                console.print("[yellow]⚠ Multiple vulnerabilities found. Review findings.[/yellow]")
            elif stats['vulnerabilities'] > 0:
                console.print("[yellow]⚠ Vulnerabilities found. Review findings.[/yellow]")
            else:
                console.print("[green]✅ System appears reasonably secure. Continue monitoring.[/green]")
        else:
            print("=" * 60)
            print("📊 SCAN SUMMARY")
            print("=" * 60)
            print(f"Duration: {stats['duration']:.1f} seconds")
            print(f"Modules: {stats['total']}")
            print(f"Pages: {len(self.pages)}")
            print(f"Vulnerabilities: {stats['vulnerabilities']}")
            print(f"Passed: {stats['safe']}")
            print(f"Warnings: {stats['warning']}")
            print(f"Info: {stats['info']}")
            print(f"Skipped: {skipped_count}")
            print(f"Risk Score: {stats['risk_score']}%")
            print(f"Overall Severity: {stats['overall_severity']}")
            print(f"Coverage: {stats['coverage_percentage']}% ({stats['coverage_executed']}/{stats['coverage_total']})")
            auth_stats = stats.get('auth') or {}
            if auth_stats.get('detected') or auth_stats.get('state', 'none') not in ('none', ''):
                print(f"Authentication: {auth_stats.get('method_label', 'N/A')} ({auth_stats.get('state_label', 'N/A')})")
            print("=" * 60)
            
            if stats['critical'] > 0:
                print(f"🔴 CRITICAL: {stats['critical']} vulnerabilities found!")
            elif stats['vulnerabilities'] > 0:
                print(f"🟠 Vulnerabilities found: {stats['vulnerabilities']}")
            else:
                print("✅ No vulnerabilities detected!")
            
            if stats.get('overall_description'):
                print(f"\n💡 {stats['overall_description']}")
    
    def generate_reports(self):
        if RICH_AVAILABLE and console:
            console.print("\n[bold]Report Generation:[/bold]")
            console.print("  1. HTML only")
            console.print("  2. HTML + JSON")
            console.print("  3. All formats (HTML, JSON, Markdown, CSV, TXT)")
            choice = console.input("Choose format (1-3) [1]: ").strip() or "1"
        else:
            print("\nReport Generation:")
            print("  1. HTML only")
            print("  2. HTML + JSON")
            print("  3. All formats (HTML, JSON, Markdown, CSV, TXT)")
            choice = input("Choose format (1-3) [1]: ").strip() or "1"
        
        reporter = Reporter(branding=self.config.get_branding())
        reporter.generate_html(self.scan_result, self.target)
        
        if choice in ('2', '3'):
            reporter.generate_json(self.scan_result, self.target)
        
        if choice == '3':
            reporter.generate_markdown(self.scan_result, self.target)
            reporter.generate_csv(self.scan_result, self.target)
            reporter.generate_txt(self.scan_result, self.target)
        
        if RICH_AVAILABLE and console:
            console.print("[green]Reports generated in 'reports/' directory![/green]")
        else:
            print("Reports generated in 'reports/' directory!")
    
    # ---------- Authentication awareness helpers (optional, in-memory, redacted) ----------

    def _show_auth_detected(self, detection):
        reasons = list(detection.reasons)[:5]
        if RICH_AVAILABLE and console:
            lines = [f"[bold]Confidence: [cyan]{detection.confidence}%[/cyan][/bold]", "[dim]Reasons:[/dim]"]
            for r in reasons:
                lines.append(f"[dim]  • {r}[/dim]")
            if detection.framework:
                lines.append(f"[dim]  • Framework: {detection.framework}[/dim]")
            console.print(Panel("\n".join(lines), title="🔐 Authentication Detected", border_style="yellow"))
        else:
            print("\n🔐 Authentication Detected")
            print(f"Authentication Confidence: {detection.confidence}%")
            print("Reasons:")
            for r in reasons:
                print(f"  • {r}")
            if detection.framework:
                print(f"  • Framework: {detection.framework}")

    def _auth_detection_phase(self):
        if getattr(self.config, 'auth_detection', True) is False:
            return
        from core.auth_manager import AuthDetector
        try:
            self.session.classify_responses = True
            self.session.response_classifications = []
            detector = AuthDetector(session=self.session)
            detection = detector.probe(self.target, session=self.session,
                                       timeout=min(getattr(self.config, 'request_timeout', 30) or 30, 10))
            self._auth_probe_classifications = list(self.session.response_classifications)
            self.session.response_classifications = []
            self.auth_detection = detection
            self.scan_result.set_auth_detection(detection)
            for c in self._auth_probe_classifications:
                self.scan_result.record_auth_response(c)
            if detection.detected:
                self._show_auth_detected(detection)
        except Exception as e:
            logger.debug("Auth detection skipped: %s", e)

    def _auth_decision_phase(self):
        if not self.auth_detection or not self.auth_detection.detected:
            return
        crawl_classifications = []
        for c in getattr(self.session, 'response_classifications', []):
            self.scan_result.record_auth_response(c)
            crawl_classifications.append(c)
        self.session.response_classifications = []
        from core.auth_manager import AuthDecisionEngine
        decision = AuthDecisionEngine().analyze(
            self.auth_detection,
            list(self._auth_probe_classifications) + crawl_classifications,
        )
        self.auth_decision = decision
        self.scan_result.auth_est_improvement = decision.improvement
        self.scan_result.auth_coverage_public = decision.public_coverage
        self.scan_result.auth_public_coverage_estimate = decision.public_coverage
        self.scan_result.auth_public_pages = len({p['url'] for p in self.pages})
        if decision.prompt and getattr(self.config, 'auth_prompt', True):
            self._auth_prompt(decision)
        elif decision.improvement > 0:
            self._show_auth_note(decision)

    def _show_auth_note(self, decision):
        if RICH_AVAILABLE and console:
            console.print(
                f"[dim]🔐 Authentication detected (confidence {decision.confidence}%) — public coverage "
                f"{decision.public_coverage}%. {decision.coverage_message()}[/dim]"
            )
        else:
            print(f"🔐 Authentication detected (confidence {decision.confidence}%) — public coverage "
                  f"{decision.public_coverage}%. {decision.coverage_message()}")

    def _show_login_detected_hint(self):
        """Non-blocking informational hint (SOP v4.0 Phase 1). Never forces auth."""
        message = ("Login page detected. You may enable authenticated scanning "
                   "to access protected areas.")
        if RICH_AVAILABLE and console:
            console.print(f"[yellow]🔐 {message}[/yellow]")
        else:
            print(f"🔐 {message}")

    def _auth_prompt(self, decision):
        import getpass
        from core.auth_manager import LoginAuthenticator, LoginProfile, SessionImporter
        if RICH_AVAILABLE and console:
            console.print(Panel(
                "[white]This website appears to require authentication to access additional content.[/white]\n"
                f"[dim]Confidence: {decision.confidence}% | Public coverage: {decision.public_coverage}%[/dim]\n"
                f"[dim]{decision.coverage_message()}[/dim]",
                title="🔐 Authentication Detected", border_style="yellow"))
            console.print("  [bold cyan]1.[/bold cyan] Continue Public Scan")
            console.print("  [bold cyan]2.[/bold cyan] Use Session Cookies")
            console.print("  [bold cyan]3.[/bold cyan] Use Bearer Token")
            console.print("  [bold cyan]4.[/bold cyan] Configure Login")
            console.print("  [bold cyan]5.[/bold cyan] Import Browser Session")
            choice = console.input("[bold yellow]Select (1-5) [1]: [/bold yellow]").strip() or "1"
        else:
            print("\n🔐 Authentication Detected")
            print("This website appears to require authentication to access additional content.")
            print(f"Confidence: {decision.confidence}% | Public coverage: {decision.public_coverage}%")
            print(decision.coverage_message())
            print("\nChoose an authentication method:")
            print("  1. Continue Public Scan")
            print("  2. Use Session Cookies")
            print("  3. Use Bearer Token")
            print("  4. Configure Login")
            print("  5. Import Browser Session")
            choice = input("Select (1-5) [1]: ").strip() or "1"

        if choice == '1':
            if RICH_AVAILABLE and console:
                console.print("[dim]Continuing with public scan.[/dim]")
            return
        if choice == '2':
            if RICH_AVAILABLE and console:
                raw = console.input("[bold yellow]Paste cookies (name=value; name2=value2): [/bold yellow]").strip()
            else:
                raw = input("Paste cookies (name=value; name2=value2): ").strip()
            if not raw:
                return
            from core.auth_manager import AuthSession
            auth = AuthSession(method='cookies')
            auth.set_cookies_from_string(raw)
            if auth.cookies:
                self._activate_auth(auth)
        elif choice == '3':
            if RICH_AVAILABLE and console:
                token = console.input("[bold yellow]Bearer token (JWT): [/bold yellow]").strip()
            else:
                token = input("Bearer token (JWT): ").strip()
            if not token:
                return
            from core.auth_manager import AuthSession
            auth = AuthSession(method='bearer')
            auth.set_bearer_token(token)
            self._activate_auth(auth)
        elif choice == '4':
            self._auth_configure_login()
        elif choice == '5':
            self._auth_import_browser()

    def _auth_configure_login(self):
        import getpass
        from core.auth_manager import LoginAuthenticator, LoginProfile
        if RICH_AVAILABLE and console:
            login_url = console.input("[bold yellow]Login URL [default target/login]: [/bold yellow]").strip()
            username = console.input("[bold yellow]Username: [/bold yellow]").strip()
        else:
            login_url = input("Login URL [default target/login]: ").strip()
            username = input("Username: ").strip()
        if not username:
            return
        password = getpass.getpass("Password: ")
        if not password:
            return
        base = self.target.rstrip('/')
        profile = LoginProfile(
            login_url=login_url or f"{base}/login",
            username=username,
            password=password,
        )
        authenticator = LoginAuthenticator(session=self.session)
        auth, _resp = authenticator.authenticate(profile)
        if auth.state.value == 'login_failed':
            if RICH_AVAILABLE and console:
                console.print(f"[red]❌ Login failed: {auth.message}[/red]")
            else:
                print(f"❌ Login failed: {auth.message}")
            self.scan_result.auth_session = auth
            return
        self._activate_auth(auth)

    def _auth_import_browser(self):
        from core.auth_manager import SessionImporter
        if RICH_AVAILABLE and console:
            console.print("[dim]Browser import reads cookies for this target domain only, "
                          "keeps them in memory, and never stores or uploads them.[/dim]")
            browser = console.input("[bold yellow]Browser (chrome/edge/firefox/brave): [/bold yellow]").strip().lower() or 'chrome'
            confirm = console.input("[bold yellow]Approve importing session cookies? (yes/no): [/bold yellow]").strip().lower()
        else:
            print("Browser import reads cookies for this target domain only, keeps them in memory, "
                  "and never stores or uploads them.")
            browser = input("Browser (chrome/edge/firefox/brave): ").strip().lower() or 'chrome'
            confirm = input("Approve importing session cookies? (yes/no): ").strip().lower()
        if confirm not in ('yes', 'y', 'approve'):
            if RICH_AVAILABLE and console:
                console.print("[dim]Browser import cancelled.[/dim]")
            else:
                print("Browser import cancelled.")
            return
        try:
            importer = SessionImporter(approval=True)
            cookie_list = importer.import_for_domain(self.target, browser=browser)
        except PermissionError as e:
            if RICH_AVAILABLE and console:
                console.print(f"[red]❌ {e}[/red]")
            else:
                print(f"❌ {e}")
            return
        except Exception as e:
            logger.debug("Browser session import failed: %s", e)
            if RICH_AVAILABLE and console:
                console.print(f"[red]❌ Browser import failed: {e}[/red]")
            else:
                print(f"❌ Browser import failed: {e}")
            return
        if not cookie_list:
            if RICH_AVAILABLE and console:
                console.print("[yellow]⚠ No cookies found for this domain.[/yellow]")
            else:
                print("⚠ No cookies found for this domain.")
            return
        from core.auth_manager import AuthSession
        auth = AuthSession(method='browser')
        for c in cookie_list:
            auth.set_cookie(c.get('name', ''), c.get('value', ''),
                            domain=c.get('domain', '') or '')
        if not auth.cookies:
            if RICH_AVAILABLE and console:
                console.print("[yellow]⚠ No cookies found for this domain.[/yellow]")
            else:
                print("⚠ No cookies found for this domain.")
            return
        self._activate_auth(auth)

    def _activate_auth(self, auth):
        self.auth_session = auth
        self.session.auth = auth
        try:
            auth.apply_to(self.session)
        except Exception as e:
            logger.debug("Could not attach auth session: %s", e)
        self.scan_result.set_auth_session(auth)
        label = auth.to_dict(redact=True).get('method_label', 'Authentication')
        if RICH_AVAILABLE and console:
            console.print(f"[green]✅ {label} active — re-crawling with session...[/green]")
        else:
            print(f"✅ {label} active — re-crawling with session...")
        self._authenticated_crawl()

    def _authenticated_crawl(self):
        public_pages = list(self.pages)
        public_urls = {p['url'] for p in public_pages}
        self.session.classify_responses = True
        self.session.response_classifications = []
        self.crawl_target()
        for c in self.session.response_classifications:
            self.scan_result.record_auth_response(c)
        self.session.response_classifications = []
        auth_pages = [p for p in self.pages if p['url'] not in public_urls]
        self.scan_result.auth_authenticated_pages = len(auth_pages)
        merged = {}
        for p in public_pages:
            merged[p['url']] = p
        for p in self.pages:
            if p['url'] not in merged:
                merged[p['url']] = p
        self.pages = list(merged.values())
        self.scan_result.auth_protected_areas = [p['url'] for p in auth_pages][:100]
        if RICH_AVAILABLE and console:
            console.print(f"[green]✅ Merged crawl: {len(public_pages)} public + {len(auth_pages)} authenticated "
                          f"= {len(self.pages)} unique pages[/green]")
        else:
            print(f"✅ Merged crawl: {len(public_pages)} public + {len(auth_pages)} authenticated "
                  f"= {len(self.pages)} unique pages")

    def _finish_auth(self):
        for c in getattr(self.session, 'response_classifications', []):
            self.scan_result.record_auth_response(c)
        self.session.response_classifications = []
        if self.auth_detection and self.auth_detection.detected and not self.auth_session:
            self.scan_result.auth_state = 'public_only'
            self.scan_result.auth_state_label = 'Public Only'
        if self.auth_session is not None:
            self.scan_result.auth_session = self.auth_session
        self.scan_result.evaluate_auth_state()
        coverage = self.scan_result.get_auth_coverage()
        self.scan_result.auth_coverage_public = coverage['public']
        self.scan_result.auth_coverage_authenticated = coverage['authenticated']
        self.scan_result.auth_coverage_overall = coverage['overall']
        self.scan_result.auth_coverage_improvement = coverage['improvement']

    def run_scan(self, target, *, auth_spec=None, report_formats=("html", "json"),
                 report_dir="reports"):
        """Non-interactive scan entry point (used by the ``sea`` CLI).

        Mirrors ``run()`` but never prompts: optional authentication is driven
        entirely by ``auth_spec`` and login detection stays informational and
        non-blocking. Anonymous scanning (no ``auth_spec``) behaves exactly as
        the default interactive flow.
        """
        self.target = target
        self.config.auth_prompt = False  # informational only in non-interactive mode
        logger.info("Scan started for target: %s", self.target)
        try:
            self.show_banner()
            self._show_playwright_status()

            # Login detection (informational). Detected -> non-blocking hint;
            # authentication is never forced.
            self._auth_detection_phase()
            if self.auth_detection and self.auth_detection.detected:
                self._show_login_detected_hint()

            auth = None
            if auth_spec is not None and getattr(auth_spec, "enabled", False):
                from core.auth import AuthenticationManager
                manager = AuthenticationManager()
                try:
                    auth = manager.build(auth_spec)
                except Exception as exc:
                    print(f"\n❌ Authentication setup failed: {exc}")
                    print("Continuing with anonymous scan.\n")
                if auth is not None:
                    # Public crawl first, then re-crawl with the session attached
                    # so protected pages are counted (auth_authenticated_pages).
                    self.crawl_target()
                    self._activate_auth(auth)
                    if getattr(auth_spec, "validate", True):
                        try:
                            result = manager.validate(auth, self.session, target)
                        except Exception as exc:
                            logger.debug("Session validation skipped: %s", exc)
                            result = None
                        if result is not None and result.applicable:
                            self.scan_result.auth_session_checked = True
                            self.scan_result.auth_session_valid = result.valid
                        if result is not None and result.applicable and not result.valid:
                            manager.mark_invalid(auth)
                            if RICH_AVAILABLE and console:
                                console.print(
                                    f"[red]⚠️ Session validation failed: {result.message}[/red]"
                                )
                                console.print("[yellow]Continuing anonymously — protected areas may be missed.[/yellow]")
                            else:
                                print(f"⚠️ Session validation failed: {result.message}")
                                print("Continuing anonymously — protected areas may be missed.")
                        elif result is not None and result.valid:
                            if RICH_AVAILABLE and console:
                                console.print(f"[green]✅ {result.message}[/green]")
                            else:
                                print(f"✅ {result.message}")
            else:
                self.crawl_target()

            logger.info("Crawl completed: %d useful pages", len(self.pages))
            self.scan_result.start_time = datetime.now()
            self.show_scan_info()
            self.run_scan_on_all_pages()
            self._finish_auth()
            # Phase A9: single assessment lifecycle.
            self.scan_result.assess()
            logger.info(
                "Assessment complete: risk=%s tier=%s",
                self.scan_result.assessment.statistics.get('risk_score'),
                self.scan_result.assessment.overall_tier,
            )
            self.show_summary()
            self.generate_reports_formats(report_formats, report_dir=report_dir)
            logger.info("Scan completed successfully for target: %s", self.target)

            if RICH_AVAILABLE and console:
                console.print("\n[bold green]🎉 Scan completed successfully![/bold green]")
            else:
                print("\n🎉 Scan completed successfully!")

        except KeyboardInterrupt:
            if RICH_AVAILABLE and console:
                console.print("\n[red]⚠️ Scan interrupted by user.[/red]")
            else:
                print("\n⚠️ Scan interrupted by user.")
            sys.exit(1)
        except Exception as e:
            if RICH_AVAILABLE and console:
                console.print(f"\n[red]❌ Error: {e}[/red]")
                import traceback
                console.print(traceback.format_exc())
            else:
                print(f"\n❌ Error: {e}")
                import traceback
                traceback.print_exc()
            sys.exit(1)
        finally:
            if self.browser_manager:
                self.browser_manager.stop()

    def generate_reports_formats(self, formats=("html", "json"), report_dir="reports"):
        """Non-interactive report generation for a fixed list of formats."""
        reporter = Reporter(branding=self.config.get_branding())
        if report_dir:
            try:
                os.makedirs(report_dir, exist_ok=True)
                reporter.report_dir = report_dir
            except Exception as exc:
                logger.warning("Could not use report dir %s: %s", report_dir, exc)
        generators = {
            "html": reporter.generate_html,
            "json": reporter.generate_json,
            "markdown": reporter.generate_markdown,
            "csv": reporter.generate_csv,
            "txt": reporter.generate_txt,
        }
        for fmt in formats:
            try:
                generators[fmt](self.scan_result, self.target)
            except KeyError:
                logger.warning("Unknown report format: %s", fmt)
            except Exception as exc:
                logger.error("Report generation failed for %s: %s", fmt, exc)
        if RICH_AVAILABLE and console:
            console.print("[green]Reports generated in 'reports/' directory![/green]")
        else:
            print("Reports generated in 'reports/' directory!")

    def run(self):
        try:
            logger.info("Scan started for target: %s", self.target)
            self.show_banner()
            self._show_playwright_status()
            self.target = self.get_target()
            logger.info("Target: %s", self.target)
            self._prompt_js_crawler()
            self._auth_detection_phase()
            self.post_data = self.get_post_data()
            if self.post_data:
                logger.info("POST data provided: %d fields", len(self.post_data))
            self.crawl_target()
            logger.info("Crawl completed: %d useful pages", len(self.pages))
            self._auth_decision_phase()
            self.scan_result.start_time = datetime.now()
            self.show_scan_info()
            self.run_scan_on_all_pages()
            self._finish_auth()
            # Phase A9: single assessment lifecycle. The pipeline runs per-finding
            # engines, correlation, Risk, Coverage and the Assessment Engine and
            # stores the immutable Assessment on scan_result.assessment — the only
            # data source for the CLI summary and all report formats.
            self.scan_result.assess()
            logger.info(
                "Assessment complete: risk=%s tier=%s",
                self.scan_result.assessment.statistics.get('risk_score'),
                self.scan_result.assessment.overall_tier,
            )
            self.show_summary()
            self.generate_reports()
            logger.info("Scan completed successfully for target: %s", self.target)
            
            if RICH_AVAILABLE and console:
                console.print("\n[bold green]🎉 Scan completed successfully![/bold green]")
            else:
                print("\n🎉 Scan completed successfully!")
            
        except KeyboardInterrupt:
            if RICH_AVAILABLE and console:
                console.print("\n[red]⚠️ Scan interrupted by user.[/red]")
            else:
                print("\n⚠️ Scan interrupted by user.")
            sys.exit(1)
        except Exception as e:
            if RICH_AVAILABLE and console:
                console.print(f"\n[red]❌ Error: {e}[/red]")
                import traceback
                console.print(traceback.format_exc())
            else:
                print(f"\n❌ Error: {e}")
                import traceback
                traceback.print_exc()
            sys.exit(1)
        finally:
            if self.browser_manager:
                self.browser_manager.stop()

def _launch_gui():
    """Launch the PySide6 desktop GUI (falls back to CLI if unavailable)."""
    try:
        from gui.app import run_gui
    except ImportError as exc:
        print(f"⚠️ PySide6 not available ({exc}). Falling back to CLI.")
        return None
    return run_gui()

if __name__ == "__main__":
    if "--cli" in sys.argv or "-cli" in sys.argv or "--headless" in sys.argv:
        scanner = SeaScanner()
        scanner.run()
    else:
        exit_code = _launch_gui()
        if exit_code is not None:
            sys.exit(exit_code)
        scanner = SeaScanner()
        scanner.run()