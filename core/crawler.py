"""
Crawler — HTTP and JavaScript-aware crawling.
Falls back to HTTP-only when JS mode is disabled or Playwright unavailable.
"""

import requests
import hashlib
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

from core.browser import BrowserManager, PLAYWRIGHT_AVAILABLE

logger = logging.getLogger('SeaScanner.Crawler')

class Crawler:
    SKIP_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.avif',
        '.css', '.js', '.mjs', '.wasm',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp4', '.mp3', '.webm', '.ogg', '.wav', '.flac', '.avi', '.mov',
        '.pdf', '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.json', '.xml', '.yaml', '.yml', '.map',
        '.dll', '.exe', '.so', '.dylib', '.bin',
    }

    SKIP_CONTENT_TYPES = {
        'image/', 'video/', 'audio/', 'font/', 'application/octet-stream',
        'application/pdf', 'application/zip', 'application/x-zip',
    }

    def __init__(self, session=None, use_js: bool = False, browser_manager: BrowserManager = None):
        self.session = session or requests.Session()
        self.visited = set()
        self.content_hashes = set()
        self.pages = []
        self.use_js = use_js and PLAYWRIGHT_AVAILABLE
        self.browser_manager = browser_manager
        self.diag = {
            'crawler_type': 'js' if self.use_js and browser_manager and browser_manager.is_available else 'http',
            'urls_visited': 0,
            'urls_skipped_extension': 0,
            'urls_skipped_content_type': 0,
            'urls_skipped_status': 0,
            'urls_skipped_duplicate': 0,
            'urls_skipped_not_html': 0,
            'urls_skipped_timeout': 0,
            'urls_skipped_error': 0,
            'links_found_total': 0,
            'links_internal': 0,
            'links_external': 0,
            'links_skipped_extension': 0,
            'links_skipped_hash': 0,
            'pages_useful': 0,
            'pages_not_useful': 0,
            'forms_discovered': 0,
            'hidden_inputs_discovered': 0,
        }

    def crawl(self, start_url: str, max_pages: int = 30, js_wait_seconds: int = 3):
        self.visited = set()
        self.content_hashes = set()
        self.pages = []
        self.diag = {k: 0 for k in self.diag}

        if self.use_js and self.browser_manager and self.browser_manager.is_available:
            self.diag['crawler_type'] = 'js'
            from core.js_crawler import JSCrawler
            js_crawler = JSCrawler(self.browser_manager, session=self.session, diagnostics=self.diag)
            self.pages = js_crawler.crawl(start_url, max_pages, js_wait_seconds)
            return self.pages

        self.diag['crawler_type'] = 'http'
        logger.info("HTTP crawler starting: %s (max_pages=%d)", start_url, max_pages)
        self._crawl_recursive(start_url, max_pages)
        logger.info("HTTP crawler finished: visited=%d useful=%d not_useful=%d skipped_ext=%d skipped_ct=%d skipped_status=%d skipped_dup=%d",
                    self.diag['urls_visited'], self.diag['pages_useful'], self.diag['pages_not_useful'],
                    self.diag['urls_skipped_extension'], self.diag['urls_skipped_content_type'],
                    self.diag['urls_skipped_status'], self.diag['urls_skipped_duplicate'])
        return self.pages

    def extract_post_forms(self, url: str) -> list:
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code != 200:
                return []
            soup = BeautifulSoup(resp.text, 'html.parser')
            return self._extract_forms(soup, url)
        except Exception:
            return []

    def _should_skip_by_extension(self, url: str) -> bool:
        """تحديد ما إذا كان يجب تخطي الرابط بناءً على الامتداد"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        for ext in self.SKIP_EXTENSIONS:
            if path.endswith(ext):
                return True
        return False

    def _should_skip_by_content_type(self, response) -> bool:
        """تحديد التخطي بناءً على Content-Type"""
        content_type = response.headers.get('Content-Type', '').lower()
        for skip_type in self.SKIP_CONTENT_TYPES:
            if content_type.startswith(skip_type):
                return True
        return False

    def _is_useful_page(self, soup, url: str) -> bool:
        """
        تحديد ما إذا كانت الصفحة تستحق الفحص:
        - تحتوي على نموذج (<form>)
        - أو تحتوي على معاملات في الرابط (?)
        - أو تحتوي على مدخلات (<input>, <textarea>, <select>)
        """
        # إذا كان هناك معاملات في الرابط
        if '?' in url and parse_qs(urlparse(url).query):
            return True

        # إذا كان هناك نموذج POST
        if soup.find('form', method=lambda m: m and m.lower() == 'post'):
            return True

        # إذا كان هناك أي عنصر إدخال (حتى لو لم يكن داخل form)
        if soup.find_all(['input', 'textarea', 'select']):
            return True

        return False

    def _crawl_recursive(self, url: str, max_pages: int):
        if len(self.visited) >= max_pages:
            logger.debug("  Queue full: visited %d/%d pages, stopping", len(self.visited), max_pages)
            return

        if url in self.visited:
            return

        if self._should_skip_by_extension(url):
            self.diag['urls_skipped_extension'] += 1
            logger.debug("  Skip [extension]: %s", url)
            return

        self.visited.add(url)
        self.diag['urls_visited'] += 1
        logger.debug("  Visit #%d: %s", self.diag['urls_visited'], url)

        try:
            response = self.session.get(url, timeout=5, stream=True)

            if self._should_skip_by_content_type(response):
                self.diag['urls_skipped_content_type'] += 1
                ct = response.headers.get('Content-Type', '')
                logger.debug("  Skip [content-type: %s]: %s", ct, url)
                return

            if response.status_code != 200:
                self.diag['urls_skipped_status'] += 1
                logger.debug("  Skip [HTTP %d]: %s", response.status_code, url)
                return

            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type:
                self.diag['urls_skipped_not_html'] += 1
                logger.debug("  Skip [not HTML: %s]: %s", content_type, url)
                return

            soup = BeautifulSoup(response.text, 'html.parser')

            # Duplicate content check
            content_hash = hashlib.md5(response.text.encode(), usedforsecurity=False).hexdigest()
            if content_hash in self.content_hashes:
                self.diag['urls_skipped_duplicate'] += 1
                logger.debug("  Skip [duplicate content]: %s", url)
                return
            self.content_hashes.add(content_hash)

            # Usefulness
            is_useful = self._is_useful_page(soup, url)
            if is_useful:
                self.diag['pages_useful'] += 1
                params = self._extract_params(url)
                forms = self._extract_forms(soup, url)
                self.diag['forms_discovered'] += len(forms)
                for form in forms:
                    for field_name in form.get('fields', {}):
                        if 'hidden' in str(field_name).lower() or 'hidd' in str(field_name).lower():
                            self.diag['hidden_inputs_discovered'] += 1
                self.pages.append({
                    'url': url,
                    'params': params,
                    'forms': forms,
                    'status': response.status_code,
                    'title': soup.title.string if soup.title else ''
                })
                logger.debug("  -> USEFUL (params=%d forms=%d)", len(params), len(forms))
            else:
                self.diag['pages_not_useful'] += 1
                reasons = []
                if '?' not in url or not parse_qs(urlparse(url).query):
                    reasons.append('no params')
                if not soup.find('form', method=lambda m: m and m.lower() == 'post'):
                    reasons.append('no POST forms')
                if not soup.find_all(['input', 'textarea', 'select']):
                    reasons.append('no inputs')
                logger.debug("  -> NOT useful: %s", ', '.join(reasons))

            # Extract links
            links_found = 0
            links_internal = 0
            links_external = 0
            links_skipped_ext = 0
            links_skipped_hash = 0
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                full_url = urljoin(url, href)
                links_found += 1

                if not self._is_internal(full_url, url):
                    links_external += 1
                    continue

                links_internal += 1

                if '#' in full_url:
                    links_skipped_hash += 1
                    continue

                if self._should_skip_by_extension(full_url):
                    links_skipped_ext += 1
                    continue

                self._crawl_recursive(full_url, max_pages)

            self.diag['links_found_total'] += links_found
            self.diag['links_internal'] += links_internal
            self.diag['links_external'] += links_external
            self.diag['links_skipped_extension'] += links_skipped_ext
            self.diag['links_skipped_hash'] += links_skipped_hash
            logger.debug("  Links: %d total, %d internal, %d external, %d skipped-ext, %d skipped-hash",
                         links_found, links_internal, links_external, links_skipped_ext, links_skipped_hash)

        except requests.exceptions.Timeout:
            self.diag['urls_skipped_timeout'] += 1
            logger.debug("  Timeout: %s", url)
            print(f"⏱️ Timeout crawling {url}, skipping...")
        except Exception as e:
            self.diag['urls_skipped_error'] += 1
            logger.debug("  Error crawling %s: %s", url, str(e))

    def _extract_params(self, url: str) -> dict:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}

    def _extract_forms(self, soup, base_url: str) -> list:
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()

            if method != 'post':
                continue

            full_url = urljoin(base_url, action)

            fields = {}
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if not name:
                    continue
                fields[name] = self._generate_value(input_tag)

            # تجاهل النماذج الفارغة
            if fields:
                forms.append({
                    'url': full_url,
                    'fields': fields
                })

        return forms

    def _generate_value(self, tag) -> str:
        input_type = tag.get('type', 'text').lower()
        name = tag.get('name', '').lower()

        if tag.get('value'):
            return tag.get('value')

        if input_type == 'email' or 'email' in name:
            return 'test@example.com'
        elif input_type == 'password' or 'password' in name or 'pass' in name:
            return 'Password123!'
        elif 'phone' in name or 'tel' in name:
            return '01000000000'
        elif 'date' in name:
            return '2024-01-01'
        elif 'number' in name or 'age' in name:
            return '25'
        elif input_type == 'checkbox':
            return 'on'
        elif input_type == 'radio':
            return tag.get('value', 'on')
        elif tag.name == 'select':
            options = tag.find_all('option')
            if options:
                return options[0].get('value', '')
            return '1'
        elif 'search' in name or name == 'q':
            return 'test'
        elif 'comment' in name or 'message' in name or 'content' in name:
            return 'This is a test message.'
        else:
            return 'test'

    def _is_internal(self, url: str, base_url: str) -> bool:
        parsed_url = urlparse(url)
        parsed_base = urlparse(base_url)
        if not parsed_url.netloc:
            return True
        return parsed_url.netloc == parsed_base.netloc