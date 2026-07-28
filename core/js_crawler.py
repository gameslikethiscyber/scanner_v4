import json
import hashlib
import re
import logging
from urllib.parse import urljoin, urlparse, parse_qs
from core.browser import BrowserManager, PLAYWRIGHT_AVAILABLE

logger = logging.getLogger('SeaScanner.JSCrawler')

class JSCrawler:
    JS_SKIP_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.avif',
        '.css', '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp4', '.mp3', '.webm', '.ogg', '.wav', '.flac', '.avi', '.mov',
        '.pdf', '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
        '.dll', '.exe', '.so', '.dylib', '.bin',
    }

    API_PATTERN = re.compile(r'(/api/|/v\d+/|/graphql|/rest/|/endpoint)', re.IGNORECASE)

    def __init__(self, browser_manager: BrowserManager, session=None, diagnostics: dict = None):
        self.browser = browser_manager
        self.session = session
        self.visited = set()
        self.content_hashes = set()
        self.pages = []
        self.xhr_urls = set()
        self.api_endpoints = set()
        self.js_variables = {}
        self.diag = diagnostics if diagnostics is not None else {
            'crawler_type': 'js',
            'urls_visited': 0,
            'pages_useful': 0,
            'pages_not_useful': 0,
            'links_found_total': 0,
            'forms_discovered': 0,
            'hidden_inputs_discovered': 0,
        }

    def crawl(self, start_url: str, max_pages: int = 30, wait_seconds: int = 3):
        self.visited = set()
        self.content_hashes = set()
        self.pages = []
        self.xhr_urls = set()
        self.api_endpoints = set()
        self.js_variables = {}
        self.diag.update({
            'urls_visited': 0,
            'pages_useful': 0,
            'pages_not_useful': 0,
            'links_found_total': 0,
            'forms_discovered': 0,
            'hidden_inputs_discovered': 0,
        })

        if not self.browser.is_available:
            logger.warning("Browser not available — JSCrawler returning empty pages")
            return self.pages

        logger.info("JSCrawler starting crawl: %s (max_pages=%d, wait=%ds)", start_url, max_pages, wait_seconds)
        self._crawl_js_recursive(start_url, max_pages, wait_seconds)
        self._capture_xhr_endpoints()
        logger.info("JSCrawler finished: %d pages, %d XHR/Fetch requests captured, %d API endpoints",
                    len(self.pages), len(self.xhr_urls), len(self.api_endpoints))
        return self.pages

    def _crawl_js_recursive(self, url: str, max_pages: int, wait_seconds: int):
        if len(self.pages) >= max_pages:
            return
        normalized = url.split('#')[0]
        if normalized in self.visited:
            return
        self.visited.add(normalized)

        if self._should_skip_by_extension(url):
            return

        page = self.browser.get_page()
        if page is None:
            return
        try:
            xhr_captures = []
            def handle_response(response):
                req = response.request
                if req.resource_type in ('xhr', 'fetch'):
                    xhr_captures.append({
                        'url': req.url,
                        'method': req.method,
                        'status': response.status,
                    })
                    self.xhr_urls.add(req.url)
                    if self.API_PATTERN.search(req.url):
                        self.api_endpoints.add(req.url)

            page.on('response', handle_response)
            page.goto(url, wait_until='networkidle', timeout=30000)
            page.wait_for_timeout(wait_seconds * 1000)

            page.evaluate('() => document.querySelectorAll("img, picture, video, source").forEach(e => e.remove())')

            content = page.content()
            text_content = page.evaluate('() => document.body ? document.body.innerText : ""')
            page_url = page.url

            content_hash = hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()
            if content_hash in self.content_hashes:
                self.browser.close_page(page)
                return
            self.content_hashes.add(content_hash)

            dynamic_links = self._extract_dynamic_links(page)
            dynamic_forms = self._extract_dynamic_forms(page, page_url)
            js_vars = self._extract_js_variables(page)
            self.js_variables[page_url] = js_vars

            self.diag['urls_visited'] += 1
            self.diag['links_found_total'] += len(dynamic_links)
            self.diag['forms_discovered'] += len(dynamic_forms)

            for form in dynamic_forms:
                for field_name in form.get('fields', {}):
                    if 'hidden' in str(field_name).lower() or 'hidd' in str(field_name).lower():
                        self.diag['hidden_inputs_discovered'] += 1

            is_spa = self._is_spa_page(page)
            logger.debug("  Page: %s | links=%d forms=%d js_vars=%d xhr=%d spa=%s",
                         page_url, len(dynamic_links), len(dynamic_forms),
                         len(js_vars), len(xhr_captures), is_spa)

            params = self._extract_params(page_url)

            if params or dynamic_forms or js_vars:
                self.diag['pages_useful'] += 1
                self.pages.append({
                    'url': page_url,
                    'params': params,
                    'forms': dynamic_forms,
                    'js_variables': js_vars,
                    'xhr_endpoints': list(xhr_captures),
                    'content': content,
                })
                logger.debug("  -> USEFUL (params=%d forms=%d js_vars=%d)", len(params), len(dynamic_forms), len(js_vars))
            else:
                self.diag['pages_not_useful'] += 1
                logger.debug("  -> NOT useful: no params, no forms, no js_vars")

            if not is_spa:
                for link in dynamic_links:
                    full_url = urljoin(page_url, link)
                    if self._should_skip_by_extension(full_url):
                        continue
                    if not self._is_internal(full_url, start_url):
                        continue
                    self._crawl_js_recursive(full_url, max_pages, wait_seconds)
            else:
                for link in dynamic_links:
                    full_url = urljoin(page_url, link)
                    if self._is_internal(full_url, start_url) and full_url not in self.visited:
                        self._crawl_js_recursive(full_url, max_pages, wait_seconds)

        except Exception as e:
            logger.debug("  Error crawling %s: %s", url, str(e))
        finally:
            self.browser.close_page(page)

    def _extract_dynamic_links(self, page):
        links = set()
        try:
            anchors = page.evaluate('''() => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    if (a.href) links.push(a.href);
                });
                return links;
            }''')
            links.update(anchors)

            js_links = page.evaluate('''() => {
                const urls = [];
                document.querySelectorAll('[data-href], [data-url], [data-link], [router-link]').forEach(el => {
                    const val = el.getAttribute('data-href') || el.getAttribute('data-url') || el.getAttribute('data-link') || el.getAttribute('router-link');
                    if (val) urls.push(val);
                });
                return urls;
            }''')
            links.update(js_links)

            script_urls = page.evaluate('''() => {
                const urls = [];
                document.querySelectorAll('script[src]').forEach(s => {
                    if (s.src) urls.push(s.src);
                });
                return urls;
            }''')
            links.update(script_urls)
        except Exception:
            pass
        return list(links)

    def _extract_dynamic_forms(self, page, base_url):
        forms = []
        try:
            form_data = page.evaluate('''(baseUrl) => {
                const results = [];
                document.querySelectorAll('form').forEach(form => {
                    const fields = {};
                    form.querySelectorAll('input, textarea, select').forEach(input => {
                        const name = input.getAttribute('name');
                        if (name) {
                            let val = input.value || input.getAttribute('value') || '';
                            if (val === '' && input.type === 'checkbox') val = 'on';
                            fields[name] = val;
                        }
                    });
                    if (Object.keys(fields).length > 0) {
                        results.push({
                            url: form.action ? new URL(form.action, baseUrl).href : baseUrl,
                            method: (form.method || 'get').toLowerCase(),
                            fields: fields,
                        });
                    }
                });
                return results;
            }''', base_url)
            for fd in form_data:
                if fd['method'] == 'post' and fd.get('fields'):
                    forms.append({'url': fd['url'], 'fields': fd['fields']})
        except Exception:
            pass
        return forms

    def _extract_js_variables(self, page):
        vars_dict = {}
        try:
            vars_dict = page.evaluate('''() => {
                const result = {};
                const patterns = [
                    /(?:var|let|const)\s+(\w+)\s*=\s*['"]([^'"]+)['"]/g,
                    /(?:api|endpoint|baseUrl|baseURL|base_url)\s*[:=]\s*['"]([^'"]+)['"]/g,
                    /(?:token|key|secret)\s*[:=]\s*['"]([^'"]+)['"]/gi,
                ];
                const scripts = document.querySelectorAll('script:not([src])');
                scripts.forEach(script => {
                    const text = script.textContent || '';
                    patterns.forEach(pattern => {
                        let m;
                        while ((m = pattern.exec(text)) !== null) {
                            result[m[1]] = m[2];
                        }
                    });
                    const urlMatches = text.match(/["']((?:https?:\/\/|\/)[^"']*(?:api|rest|graphql|endpoint)[^"']*)["']/gi);
                    if (urlMatches) {
                        urlMatches.forEach(u => {
                            const clean = u.replace(/["']/g, '');
                            result['endpoint_' + Object.keys(result).length] = clean;
                        });
                    }
                });
                return result;
            }''')
        except Exception:
            pass
        return vars_dict

    def _is_spa_page(self, page):
        try:
            has_router = page.evaluate('''() => {
                return !!(window.__NUXT__ || window.__NEXT_DATA__ || window.__VUE_DEVTOOLS_GLOBAL_HOOK__
                    || window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || window.angular || window.Router
                    || document.querySelector('[data-reactroot]')
                    || document.querySelector('#__next') || document.querySelector('[ng-app]')
                    || document.querySelector('[ng-version]'));
            }''')
            return has_router
        except Exception:
            return False

    def _capture_xhr_endpoints(self):
        pass

    def _should_skip_by_extension(self, url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.lower()
        for ext in self.JS_SKIP_EXTENSIONS:
            if path.endswith(ext):
                return True
        return False

    def _extract_params(self, url: str) -> dict:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}

    def _is_internal(self, url: str, base_url: str) -> bool:
        parsed_url = urlparse(url)
        parsed_base = urlparse(base_url)
        if not parsed_url.netloc:
            return True
        return parsed_url.netloc == parsed_base.netloc
