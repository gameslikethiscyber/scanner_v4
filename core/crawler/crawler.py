"""
Crawler — advanced smart crawling engine (SOP v4.0 Phase 2).

Discovery sources:
- HTML links / anchors / navigation menus / form actions
- canonical links and meta-refresh redirect targets
- JS links (basic static extraction only — no rendering)
- sitemap.xml (merged into the queue, de-duplicated)
- robots.txt (parsed; used for Sitemap references & optional policy)

The engine is a bounded breadth-first crawler driven by an explicit queue with
depth limits, configurable scope, configurable budgets (pages / requests /
duration) and three de-duplication layers. The public API and diagnostics
dictionary remain backward compatible with the legacy ``Crawler`` so callers
in ``main.py`` and the GUI ``ScanWorker`` consume it identically.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from core.browser import BrowserManager, PLAYWRIGHT_AVAILABLE
from core.crawler.crawl_statistics import CrawlStatistics
from core.crawler.deduplicator import Deduplicator
from core.crawler.link_discovery import LinkDiscovery
from core.crawler.page_classifier import PageClassifier
from core.crawler.queue import CrawlQueue
from core.crawler.robots_parser import RobotsParser
from core.crawler.scope_manager import ScopeManager, SCOPE_DOMAIN
from core.crawler.sitemap_parser import SitemapParser
from core.crawler.url_normalizer import URLNormalizer

logger = logging.getLogger("SeaScanner.Crawler")


class Crawler:
    SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
        ".css", ".js", ".mjs", ".wasm",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp4", ".mp3", ".webm", ".ogg", ".wav", ".flac", ".avi", ".mov",
        ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".json", ".xml", ".yaml", ".yml", ".map",
        ".dll", ".exe", ".so", ".dylib", ".bin",
    }

    SKIP_CONTENT_TYPES = {
        "image/", "video/", "audio/", "font/", "application/octet-stream",
        "application/pdf", "application/zip", "application/x-zip",
    }

    def __init__(self, session=None, use_js: bool = False, browser_manager: BrowserManager = None,
                 cookies: Optional[List[Dict[str, str]]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 scope: str = SCOPE_DOMAIN,
                 include_subdomains: bool = False,
                 include_patterns: Optional[list] = None,
                 exclude_patterns: Optional[list] = None,
                 max_depth: Optional[int] = None,
                 max_requests: Optional[int] = None,
                 max_duration: Optional[float] = None,
                 crawl_strategy: str = "breadth",
                 respect_robots: bool = False,
                 parse_sitemap: bool = True,
                 timeout: float = 5.0):
        self.session = session or requests.Session()
        self.use_js = use_js and PLAYWRIGHT_AVAILABLE
        self.browser_manager = browser_manager
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self._apply_cookies(cookies)

        # crawl configuration knobs
        self.scope_option = scope
        self.include_subdomains = include_subdomains
        self.include_patterns = list(include_patterns) if include_patterns else []
        self.exclude_patterns = list(exclude_patterns) if exclude_patterns else []
        self.max_depth = max_depth
        self.max_requests = max_requests
        self.max_duration = max_duration
        self.crawl_strategy = crawl_strategy or "breadth"
        self.respect_robots = respect_robots
        self.parse_sitemap = parse_sitemap
        self.timeout = timeout

        # subsystem collaborators
        self.normalizer = URLNormalizer()
        self.links = LinkDiscovery()
        self.classifier = PageClassifier()
        self.stats = CrawlStatistics()
        self._robots_parser = RobotsParser()
        self._sitemap_parser = SitemapParser()

        # attributes read by callers / engine
        self.visited = set()
        self.content_hashes = set()
        self.pages = []
        self.scope = None
        self.attack_surface = {"urls": [], "classifications": {}}
        self.diag = {}
        self._start_url = ""

    # ------------------------------------------------------------- public
    def crawl(self, start_url: str, max_pages: int = 30, js_wait_seconds: int = 3):
        self._reset(start_url)

        if self._use_js():
            return self._crawl_js(start_url, max_pages, js_wait_seconds)

        logger.info("Crawler starting: %s (max_pages=%d, scope=%s)",
                    start_url, max_pages, self.scope.describe() if self.scope else "?")
        self._crawl_http(start_url, max_pages)
        logger.info("Crawler finished: scanned=%d useful=%d",
                    self.stats.urls_scanned, self.stats.pages_useful)
        return self.pages

    def extract_post_forms(self, url: str) -> list:
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code != 200:
                return []
            soup = BeautifulSoup(resp.text, "html.parser")
            return self.links.extract_forms(soup, url)
        except Exception:
            return []

    # ------------------------------------------------------------- setup
    def _reset(self, start_url: str) -> None:
        self.visited = set()
        self.content_hashes = set()
        self.pages = []
        self.attack_surface = {"urls": [], "classifications": {}}
        self.stats.reset()
        self._start_url = start_url
        self.scope = ScopeManager(
            start_url,
            scope=self.scope_option,
            include_subdomains=self.include_subdomains,
            include_patterns=self.include_patterns,
            exclude_patterns=self.exclude_patterns,
        )

    def _use_js(self) -> bool:
        return self.use_js and self.browser_manager \
            and self.browser_manager.is_available and PLAYWRIGHT_AVAILABLE

    def _crawl_js(self, start_url: str, max_pages: int, js_wait_seconds: int) -> list:
        from core.js_crawler import JSCrawler
        try:
            js_crawler = JSCrawler(self.browser_manager, session=self.session)
            self.pages = js_crawler.crawl(start_url, max_pages, js_wait_seconds)
            self.diag = self.stats.to_diag()
            self.diag["crawler_type"] = "js"
            return self.pages
        except Exception as exc:
            logger.warning("JS crawler failed (%s); falling back to HTTP", exc)
            self._crawl_http(start_url, max_pages)
            return self.pages

    # -------------------------------------------------------------- BFS
    def _crawl_http(self, start_url: str, max_pages: int) -> None:
        self.stats.start()
        seed = self.normalizer.normalize(start_url)
        if not seed:
            seed = start_url

        queue = CrawlQueue(max_depth=self.max_depth)
        queue.add(seed, 0)
        self._seed_sources(seed, queue)
        dedupe = Deduplicator(self.normalizer)

        request_budget = self.max_requests or (max_pages * 4)
        deadline = (time.monotonic() + self.max_duration) if self.max_duration else None

        while not queue.empty:
            if self._budget_reached(len(self.visited), max_pages,
                                    request_budget, deadline):
                break
            item = queue.pop()
            url, depth = item
            self._process(url, depth, queue, max_pages, dedupe)

        self.stats.finish()
        self.diag = self.stats.to_diag()
        self._build_attack_surface()

    # ------------------------------------------------------- budgets
    def _budget_reached(self, visited, budget_pages, budget_requests, deadline) -> bool:
        if budget_pages and visited >= budget_pages:
            return True
        if budget_requests and visited >= budget_requests:
            return True
        if deadline and time.monotonic() >= deadline:
            return True
        return False

    def _process(self, url: str, depth: int, queue: CrawlQueue, max_pages: int,
                 dedupe: Deduplicator) -> None:
        norm = self.normalizer.normalize(url)
        if not norm:
            return
        if self.scope is not None and not self.scope.is_in_scope(norm):
            self.stats.urls_skipped_out_of_scope += 1
            return
        if self._should_skip_by_extension(norm):
            self.stats.urls_skipped_extension += 1
            return
        if dedupe.seen_url(norm):
            self.stats.urls_skipped_duplicate += 1
            self.stats.duplicates += 1
            return

        dedupe.add_url(norm)
        self.visited.add(norm)
        self.stats.urls_scanned += 1

        try:
            t0 = time.monotonic()
            response = self.session.get(norm, timeout=self.timeout, allow_redirects=True)
            self.stats.record_latency(time.monotonic() - t0)
        except requests.exceptions.Timeout:
            self.stats.urls_skipped_timeout += 1
            self.stats.timeouts += 1
            return
        except Exception as exc:
            self.stats.urls_skipped_error += 1
            self.stats.failed += 1
            logger.debug("Error crawling %s: %s", url, exc)
            return

        # redirect handling
        if getattr(response, "history", None):
            self.stats.redirects += 1
            final = self.normalizer.normalize(response.url)
            if dedupe.seen_redirect(final):
                self.stats.redirect_loops += 1
            else:
                dedupe.add_redirect(final)

        if self._should_skip_by_content_type(response):
            self.stats.urls_skipped_content_type += 1
            return
        if response.status_code != 200:
            self.stats.urls_skipped_status += 1
            return
        ct = (response.headers.get("Content-Type") or "").lower()
        if "text/html" not in ct:
            self.stats.urls_skipped_not_html += 1
            return

        if dedupe.seen_content(response.text):
            self.stats.urls_skipped_duplicate += 1
            self.stats.duplicates += 1
            return
        dedupe.add_content(response.text)
        self.content_hashes.add(self._page_hash(response.text))

        soup = BeautifulSoup(response.text, "html.parser")
        params = self._extract_params(norm)
        forms = self.links.extract_forms(soup, norm)
        self.stats.forms_discovered += len(forms)
        for form in forms:
            for name in form.get("fields", {}):
                if "hidd" in str(name).lower():
                    self.stats.hidden_inputs_discovered += 1

        classification = self.classifier.classify(norm, soup, response.status_code)
        self.stats.classifications[classification] = self.stats.classifications.get(
            classification, 0) + 1

        useful = bool(params or forms or self._has_inputs(soup))
        page = {
            "url": norm,
            "params": params,
            "forms": forms,
            "status": response.status_code,
            "title": soup.title.string if soup.title else "",
            "classification": classification,
        }
        self.pages.append(page)
        if useful:
            self.stats.pages_useful += 1
        else:
            self.stats.pages_not_useful += 1

        self._discover_and_enqueue(soup, norm, depth, queue)

    #######################################################################
    # Discovery                                                            #
    #######################################################################
    def _discover_and_enqueue(self, soup, base_url: str, parent_depth: int,
                              queue: CrawlQueue) -> None:
        discovery = self.links.extract(soup, base_url)
        js_static = self.links.extract_js(soup, base_url)
        self.stats.links_found_total += len(discovery["links"])

        for href in discovery["links"]:
            full = urljoin(base_url, href)
            if self.scope is not None and not self.scope.is_in_scope(full):
                self.stats.links_external += 1
                continue
            self.stats.links_internal += 1
            if self._should_skip_by_extension(full):
                self.stats.links_skipped_extension += 1
                continue
            norm_full = self.normalizer.normalize(full)
            if norm_full and norm_full not in self.visited:
                queue.add(norm_full, parent_depth + 1)

        for extra in (discovery.get("canonical"), discovery.get("meta_redirect")):
            if not extra:
                continue
            norm_extra = self.normalizer.normalize(extra)
            if not norm_extra:
                continue
            if self.scope is not None and not self.scope.is_in_scope(norm_extra):
                continue
            if not self._is_internal(norm_extra, base_url):
                continue
            if norm_extra not in self.visited:
                queue.add(norm_extra, parent_depth + 1)

        for u in js_static:
            norm_u = self.normalizer.normalize(u)
            if not norm_u:
                continue
            self.stats.js_urls_discovered += 1
            if self.scope is not None and not self.scope.is_in_scope(norm_u):
                continue
            if self._should_skip_by_extension(norm_u):
                continue
            if norm_u not in self.visited:
                queue.add(norm_u, parent_depth + 1)

        for script in soup.find_all("script", src=True):
            if script.get("src"):
                self.stats.js_files += 1

    # ---------------------------------------------------- seed sources
    def _seed_sources(self, seed: str, queue: CrawlQueue) -> None:
        robots = None
        if self.respect_robots or self.parse_sitemap:
            robots = self._robots_parser.fetch(self.session, seed)
            if robots:
                self.stats.robots_parsed = True
                self.stats.robots_entries = len(robots.allow) + len(robots.disallow)

        sitemap_sources = []
        if robots and robots.sitemaps:
            sitemap_sources.extend(robots.sitemaps)
        if self.parse_sitemap:
            sitemap_sources.append(seed.rstrip("/") + "/sitemap.xml")

        if not self.parse_sitemap:
            return

        for sitemap_url in sitemap_sources:
            found = self._sitemap_parser.fetch(self.session, sitemap_url,
                                               scope=self.scope)
            if found:
                self.stats.sitemap_parsed = True
                self.stats.sitemap_entries += len(found)
                for u in found:
                    if u in self.visited:
                        continue
                    queue.add(u, 0)

    # ------------------------------------------------------ helpers
    @staticmethod
    def _has_inputs(soup) -> bool:
        return bool(soup.find_all(["input", "textarea", "select"]))

    def _should_skip_by_extension(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in self.SKIP_EXTENSIONS)

    def _should_skip_by_content_type(self, response) -> bool:
        ct = (response.headers.get("Content-Type") or "").lower()
        return any(ct.startswith(skip) for skip in self.SKIP_CONTENT_TYPES)

    @staticmethod
    def _extract_params(url: str) -> dict:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}

    def _is_internal(self, url: str, base_url: str) -> bool:
        au = self.normalizer.host_of(url)
        bu = self.normalizer.host_of(base_url)
        return bool(au) and au == bu

    def _apply_cookies(self, cookies):
        for cookie in cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            domain = cookie.get("domain", "")
            if name and value:
                self.session.cookies.set(name, value, domain=domain)

    def _build_attack_surface(self):
        self.attack_surface = {
            "urls": [p["url"] for p in self.pages],
            "classifications": dict(self.stats.classifications),
        }

    @staticmethod
    def _page_hash(text: str) -> str:
        return hashlib.md5(text.encode("utf-8", errors="replace"),
                           usedforsecurity=False).hexdigest()