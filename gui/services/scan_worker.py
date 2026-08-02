"""
Scan worker — runs the existing scanner engine inside a QThread.

This is a presentation-layer orchestrator: it does NOT modify the engine. It
imports the same ``core`` / ``scanners`` modules the CLI uses and re-emits
progress, logs, module lifecycle and completion events as Qt signals so the
GUI stays fully responsive.
"""

import logging
import os
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlencode, urlparse

from PySide6.QtCore import QObject, Signal, Slot

logger = logging.getLogger("SeaScanner.GUI.Worker")

# GUI-only presets that map onto ScanConfig fields. Detection logic untouched.
SCAN_MODES = {
    "quick": {
        "label": "Quick Scan",
        "max_pages": 5,
        "max_workers": 3,
        "use_js_crawler": False,
        "request_timeout": 10,
    },
    "standard": {
        "label": "Standard Scan",
        "max_pages": 30,
        "max_workers": 5,
        "use_js_crawler": False,
        "request_timeout": 15,
    },
    "deep": {
        "label": "Deep Scan",
        "max_pages": 60,
        "max_workers": 8,
        "use_js_crawler": True,
        "request_timeout": 20,
    },
}

STAGE_LABELS = {
    "HeadersScanner": "Checking Headers...",
    "TLSScanner": "Checking TLS/SSL...",
    "DNSScanner": "Checking DNS...",
    "PortsScanner": "Checking Open Ports...",
    "SecurityTxtScanner": "Checking security.txt...",
    "TechDetectScanner": "Detecting Technologies...",
    "SensitiveFilesScanner": "Checking Sensitive Files...",
    "SQLiScanner": "Testing SQL Injection...",
    "XSSScanner": "Testing XSS...",
    "CookiesScanner": "Auditing Cookie Security...",
    "CORSScanner": "Testing CORS Configuration...",
    "CSRFScanner": "Checking CSRF Protection...",
    "LFIScanner": "Testing LFI...",
    "SSRFScanner": "Testing SSRF...",
    "HTTPMethodsScanner": "Testing HTTP Methods...",
    "OpenRedirectScanner": "Testing Open Redirect...",
    "HostHeaderScanner": "Testing Host Header Injection...",
    "SourceLeaksScanner": "Scanning for Source Code Leaks...",
    "SSTIScanner": "Testing SSTI...",
}

HOST_PROGRESS_START = 20
PAGE_PROGRESS_START = 35
CORRELATE_PROGRESS = 85
REPORT_PROGRESS = 90
DONE_PROGRESS = 100


class ScanCancelled(Exception):
    """Raised inside the worker when the user cancels the scan."""


class ScanWorker(QObject):
    stage_changed = Signal(str)
    progress = Signal(int, str)
    log = Signal(str, str)                  # level, message
    module_started = Signal(str, str)       # module name, stage label
    module_finished = Signal(str, str, str)  # module, status, detail
    finished = Signal(object)               # summary dict
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, target: str, mode: str, thread_count: int, timeout: int,
                 outputs: dict, report_dir: str, branding: dict = None,
                 auth_spec=None, crawl: dict = None):
        super().__init__()
        self.target = target
        self.mode = SCAN_MODES.get(mode, SCAN_MODES["standard"])
        self.thread_count = max(1, int(thread_count))
        self.timeout = max(1, int(timeout))
        self.outputs = outputs or {"html": True, "pdf": False}
        self.report_dir = report_dir or ""
        self.branding = branding or {}
        self.auth_spec = auth_spec
        self.crawl = crawl or {}
        self._cancel = threading.Event()

    # ---------- public control ----------
    def cancel(self) -> None:
        self._cancel.set()

    # ---------- helpers ----------
    def _check_cancelled(self) -> None:
        if self._cancel.is_set():
            raise ScanCancelled()

    def _emit_log(self, level: str, message: str) -> None:
        self.log.emit(level, message)

    def _emit_progress(self, value: int, message: str) -> None:
        self.progress.emit(int(max(0, min(100, value))), message)

    @staticmethod
    def _normalize_target(target: str) -> str:
        target = (target or "").strip()
        if not target:
            raise ValueError("Target URL cannot be empty.")
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        parsed = urlparse(target)
        if not parsed.netloc or "." not in (parsed.netloc.split(":")[0] or "."):
            raise ValueError(f"'{target}' is not a valid URL. Use a hostname like example.com")
        return target

    @staticmethod
    def _get_host(target: str) -> str:
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"

    # ---------- pipeline ----------
    @Slot()
    def run(self) -> None:
        start_wall = time.monotonic()
        try:
            self.target = self._normalize_target(self.target)
        except ValueError as exc:
            self.failed.emit(str(exc))
            return

        from core.config import ScanConfig
        from core.finding import ScanResult
        from core.http_client import TrackedSession
        from core.reporter import Reporter
        from scanners.registry import ALL_SCANNERS, HOST_LEVEL_SCANNERS, PAGE_LEVEL_SCANNERS

        try:
            from core.browser import BrowserManager, PLAYWRIGHT_AVAILABLE
        except Exception:
            BrowserManager, PLAYWRIGHT_AVAILABLE = None, False

        self._emit_log("info", f"Scan started for target: {self.target}")
        self._emit_log("info", f"Mode: {self.mode['label']} | Threads: {self.thread_count} | Timeout: {self.timeout}s")
        self.stage_changed.emit("Initializing")

        cfg = ScanConfig()
        cfg.max_pages = self.mode["max_pages"]
        cfg.max_workers = self.thread_count
        cfg.request_timeout = self.timeout
        cfg.long_request_timeout = min(int(self.timeout * 1.5), 30)
        cfg.use_js_crawler = self.mode["use_js_crawler"] and bool(PLAYWRIGHT_AVAILABLE)

        # Advanced crawl settings (SOP v4.0 Phase 2)
        crawl = self.crawl or {}
        cfg.crawl_scope = crawl.get("scope", cfg.crawl_scope)
        cfg.include_subdomains = bool(crawl.get("include_subdomains", cfg.include_subdomains))
        cfg.respect_robots = bool(crawl.get("respect_robots", cfg.respect_robots))
        cfg.parse_sitemap = bool(crawl.get("parse_sitemap", cfg.parse_sitemap))
        cfg.max_depth = crawl.get("depth", cfg.max_depth)
        cfg.max_crawl_duration = float(crawl.get("duration", cfg.max_crawl_duration))
        cfg.crawl_include_patterns = crawl.get("include_patterns",
                                               getattr(cfg, "crawl_include_patterns", []))

        session = TrackedSession()
        session.headers.update({"User-Agent": cfg.user_agent})

        scan_result = ScanResult()
        scan_result.start_time = datetime.now()
        scan_result.total_modules = len(ALL_SCANNERS)

        browser_manager = None
        try:
            if cfg.use_js_crawler and BrowserManager is not None:
                self.stage_changed.emit("Starting JS browser")
                self._emit_log("info", "JavaScript-aware crawling enabled (Playwright)")
                browser_manager = BrowserManager(headless=cfg.js_headless, max_contexts=cfg.js_max_contexts)
                started = browser_manager.start()
                if started:
                    self._emit_log("info", "Playwright browser launched successfully")
                else:
                    self._emit_log("warning", "Playwright browser failed to launch — using HTTP crawler")

            self._check_cancelled()

            # ---- Crawl phase (0% -> 20%) ----
            self.stage_changed.emit("Crawling")
            self._emit_log("info", "Crawling target...")
            self._emit_progress(3, "Crawling target...")
            pages = self._crawl_target(session, cfg, browser_manager, scan_result)
            self._emit_log("info", f"Crawl completed: {len(pages)} useful page(s)")
            self._emit_progress(HOST_PROGRESS_START, f"Crawled {len(pages)} page(s)")

            # Optional authentication (SOP v4.0 Phase 1). Anonymous default:
            # without an AuthSpec this is a no-op and login detection is only an
            # informational, non-blocking message.
            auth = self._setup_auth(session, cfg, scan_result)
            if auth is not None:
                before = {p["url"] for p in pages}
                self._emit_log("info", "Re-crawling with authentication to reach protected pages...")
                pages2 = self._crawl_target(session, cfg, browser_manager, scan_result)
                merged = list(pages)
                seen = set(before)
                for p in pages2:
                    if p["url"] not in seen:
                        seen.add(p["url"])
                        merged.append(p)
                pages = merged
                protected = sum(1 for p in pages if p["url"] not in before)
                scan_result.auth_authenticated_pages = protected
                scan_result.auth_public_pages = len(before)
                scan_result.auth_protected_areas = [
                    p["url"] for p in pages if p["url"] not in before][:100]
                self._emit_log("info", f"Authenticated crawl: {protected} protected page(s) discovered")
                self._emit_progress(HOST_PROGRESS_START, f"Crawled {len(pages)} page(s)")
            elif self.auth_spec is None or not getattr(self.auth_spec, "enabled", False):
                detection = self._detect_login(scan_result)
                if detection:
                    self._emit_log(
                        "warning",
                        "Login page detected. You may enable authenticated scanning "
                        "to access protected areas.",
                    )

            self._check_cancelled()

            # ---- Host-level scan (20% -> 35%) ----
            self.stage_changed.emit("Host scan")
            self._emit_log("info", "Running host-level scanners...")
            self._run_host_scan(scan_result, session)

            self._check_cancelled()

            # ---- Page-level scan (35% -> 85%) ----
            self.stage_changed.emit("Page scan")
            self._emit_log("info", f"Scanning {len(pages)} page(s)...")
            self._run_page_scan(scan_result, session, pages, cfg.max_workers)

            self._check_cancelled()

            # ---- Finalize results ----
            scan_result.end_time = datetime.now()
            scan_result.requests_sent = session.request_count
            scan_result.evaluate_auth_state()
            coverage = scan_result.get_auth_coverage()
            scan_result.auth_coverage_public = coverage['public']
            scan_result.auth_coverage_authenticated = coverage['authenticated']
            scan_result.auth_coverage_overall = coverage['overall']
            scan_result.auth_coverage_improvement = coverage['improvement']
            scan_result.aggregate_safe_findings()

            # Phase A9: single assessment lifecycle. run_assessment_pipeline() runs
            # per-finding engines + correlation + Risk + Coverage + the Assessment
            # Engine and stores the immutable Assessment on scan_result.assessment.
            # The GUI is a presentation-only consumer and reads that object only.
            self.stage_changed.emit("Correlating")
            self._emit_log("info", "Running correlation engine...")
            self._emit_progress(CORRELATE_PROGRESS, "Running correlation...")
            scan_result.assess()
            self._emit_log(
                "info",
                "Assessment complete: "
                f"risk={scan_result.assessment.statistics.get('risk_score')} "
                f"tier={scan_result.assessment.overall_tier}",
            )

            self._check_cancelled()

            # ---- Reports (90% -> 100%) ----
            self.stage_changed.emit("Generating report")
            self._emit_progress(REPORT_PROGRESS, "Generating report...")
            report_paths = self._generate_reports(scan_result, self.target)

            self._emit_progress(98, "Finalizing results...")
            summary = self._build_summary(scan_result, report_paths, start_wall)

            self.stage_changed.emit("Completed")
            self._emit_progress(DONE_PROGRESS, "Scan completed")
            self._emit_log("info", f"Scan completed in {summary['duration']:.1f} seconds")
            self.finished.emit(summary)
        except ScanCancelled:
            self.stage_changed.emit("Cancelled")
            self._emit_log("warning", "Scan cancelled by user")
            self.cancelled.emit()
        except Exception as exc:
            logger.error("Scan failed: %s\n%s", exc, traceback.format_exc())
            self._emit_log("error", f"Scan failed: {exc}")
            self.failed.emit(str(exc))
        finally:
            if browser_manager is not None:
                try:
                    browser_manager.stop()
                except Exception:
                    pass

    # ---------- phases ----------
    def _setup_auth(self, session, cfg, scan_result):
        """Build/attach/validate the optional authentication session.

        Returns the AuthSession when authentication is enabled, else None.
        On any failure the scan continues anonymously (never blocks).
        """
        spec = self.auth_spec
        if spec is None or not getattr(spec, "enabled", False):
            return None
        from core.auth import AuthenticationManager
        manager = AuthenticationManager()
        try:
            auth = manager.build(spec)
        except Exception as exc:
            self._emit_log("warning", f"Authentication setup failed: {exc}")
            self._emit_log("warning", "Continuing with anonymous scan.")
            return None
        if auth is None:
            return None
        manager.apply_to(auth, session)
        scan_result.set_auth_session(auth)
        method_label = getattr(auth, "method", "?")
        self._emit_log("info", f"Authentication: {method_label} enabled")
        if getattr(spec, "validate", True):
            try:
                result = manager.validate(auth, session, self.target)
            except Exception as exc:
                logger.debug("Session validation skipped: %s", exc)
                result = None
            if result is not None and result.applicable:
                scan_result.auth_session_checked = True
                scan_result.auth_session_valid = result.valid
                if result.valid:
                    self._emit_log("info", f"Session validated: {result.message}")
                else:
                    manager.mark_invalid(auth)
                    self._emit_log("warning", f"Session validation failed: {result.message}")
                    self._emit_log(
                        "warning",
                        "Continuing anonymously — protected areas may be missed.",
                    )
        return auth

    def _detect_login(self, scan_result):
        """Informational login detection (never prompts, never blocks)."""
        try:
            from core.auth_manager import AuthDetector
            detector = AuthDetector(session=None)
            detection = detector.probe(
                self.target,
                timeout=min(int(self.timeout) or 10, 10),
            )
            scan_result.set_auth_detection(detection)
            return detection if getattr(detection, "detected", False) else None
        except Exception as exc:
            logger.debug("Login detection skipped: %s", exc)
            return None

    def _crawl_target(self, session, cfg, browser_manager, scan_result):
        from core.crawler import Crawler

        crawler = Crawler(
            session=session,
            use_js=cfg.use_js_crawler,
            browser_manager=browser_manager,
            scope=cfg.crawl_scope,
            include_subdomains=cfg.include_subdomains,
            include_patterns=cfg.crawl_include_patterns,
            exclude_patterns=cfg.crawl_exclude_patterns,
            max_depth=cfg.max_depth,
            max_requests=cfg.max_crawl_requests,
            max_duration=cfg.max_crawl_duration,
            crawl_strategy=cfg.crawl_strategy,
            respect_robots=cfg.respect_robots,
            parse_sitemap=cfg.parse_sitemap,
            timeout=cfg.crawl_timeout or cfg.request_timeout,
        )
        pages = crawler.crawl(
            self.target,
            max_pages=cfg.max_pages,
            js_wait_seconds=cfg.js_wait_seconds,
        )
        pre_filter_count = len(pages)
        pages = [p for p in pages if p.get("params") or p.get("forms") or p.get("js_variables")]
        if not pages:
            pages = [{"url": self.target, "params": {}, "forms": []}]
            self._emit_log("info", "No useful pages found — using base URL as fallback")

        diag = crawler.diag if hasattr(crawler, "diag") else {}
        sr = scan_result
        sr.crawler_type = diag.get("crawler_type", "http")
        sr.urls_discovered = list(crawler.visited) if hasattr(crawler, "visited") else []
        sr.urls_crawled = diag.get("urls_visited", 0)
        sr.urls_skipped = sum([
            diag.get("urls_skipped_extension", 0),
            diag.get("urls_skipped_content_type", 0),
            diag.get("urls_skipped_status", 0),
            diag.get("urls_skipped_duplicate", 0),
            diag.get("urls_skipped_not_html", 0),
            diag.get("urls_skipped_timeout", 0),
            diag.get("urls_skipped_error", 0),
        ])
        sr.useful_pages = diag.get("pages_useful", 0)
        sr.not_useful_pages = diag.get("pages_not_useful", 0)
        sr.forms_discovered = diag.get("forms_discovered", 0)
        sr.hidden_inputs = diag.get("hidden_inputs_discovered", 0)
        sr.params_discovered = sum(len(p.get("params", {})) for p in pages)
        sr.pages_crawled = len(pages)
        sr.js_discovered_urls = diag.get("js_discovered_urls", 0)

        sr.crawl_duration_s = diag.get("crawl_duration_s", 0.0)
        sr.crawl_duplicates = diag.get("duplicates", 0)
        sr.crawl_redirects = diag.get("redirects", 0)
        sr.crawl_failed = diag.get("failed", 0)
        sr.crawl_sitemap_entries = diag.get("sitemap_entries", 0)
        sr.crawl_robots_entries = diag.get("robots_entries", 0)
        sr.attack_surface = getattr(crawler, "attack_surface", None)
        sr.crawl_classifications = (sr.attack_surface or {}).get("classifications", {})

        if hasattr(session, "cookies"):
            sr.cookies_found = len(session.cookies)

        self._emit_log("info", f"Crawler: {diag.get('crawler_type', 'http').upper()} | "
                               f"visited={diag.get('urls_visited', '?')} | "
                               f"useful={diag.get('pages_useful', '?')} | "
                               f"before_filter={pre_filter_count}")
        return pages

    def _run_host_scan(self, scan_result, session) -> None:
        from scanners.registry import HOST_LEVEL_SCANNERS

        host = self._get_host(self.target)
        total = max(1, len(HOST_LEVEL_SCANNERS))
        self._emit_progress(HOST_PROGRESS_START, f"Host scan: {host}")

        for index, scanner_class in enumerate(HOST_LEVEL_SCANNERS, start=1):
            self._check_cancelled()
            name = scanner_class.__name__
            label = STAGE_LABELS.get(name, f"Running {name}...")
            self.stage_changed.emit(label)
            self.module_started.emit(name, label)
            self._emit_log("info", label)
            try:
                scanner = scanner_class(host, session=session)
                finding = scanner.run()
                scan_result.add_finding(finding)
                self.module_finished.emit(name, finding.status.value, finding.reason or finding.title or "")
            except Exception as exc:
                logger.error("Host scanner %s failed: %s", name, exc)
                self._emit_log("error", f"Error in {name}: {exc}")
                self.module_finished.emit(name, "error", str(exc))
            progress = HOST_PROGRESS_START + (index / total) * (PAGE_PROGRESS_START - HOST_PROGRESS_START)
            self._emit_progress(progress, label)

    def _run_page_scan(self, scan_result, session, pages, max_workers) -> None:
        from scanners.registry import PAGE_LEVEL_SCANNERS

        if not pages:
            self._emit_log("warning", "No pages to scan")
            return

        tasks = []
        for page in pages:
            if self._cancel.is_set():
                break
            page_url = page["url"]
            params = page.get("params", {})
            forms = page.get("forms", [])
            if params:
                qs = urlencode(params, doseq=True)
                page_url = page_url + ("&" if "?" in page_url else "?") + qs
            post_data = None
            if forms and forms[0].get("fields"):
                post_data = forms[0]["fields"]
            tasks.append((page_url, post_data))

        total = max(1, len(tasks))
        completed = 0
        lock = threading.Lock()

        def run_page(page_url, post_data):
            for scanner_class in PAGE_LEVEL_SCANNERS:
                if self._cancel.is_set():
                    return
                name = scanner_class.__name__
                label = STAGE_LABELS.get(name, f"Running {name}...")
                self.stage_changed.emit(label)
                self.module_started.emit(name, label)
                try:
                    scanner = scanner_class(page_url, session=session, post_data=post_data)
                    finding = scanner.run()
                    scan_result.add_finding(finding)
                    self.module_finished.emit(name, finding.status.value, finding.reason or finding.title or "")
                except Exception as exc:
                    logger.error("Page scanner %s failed on %s: %s", name, page_url, exc)
                    self._emit_log("error", f"Error in {name} ({page_url}): {exc}")
                    self.module_finished.emit(name, "error", str(exc))

        executor = None
        try:
            executor = ThreadPoolExecutor(max_workers=max_workers)
            futures = [executor.submit(run_page, url, data) for url, data in tasks]
            for future in as_completed(futures):
                if self._cancel.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise ScanCancelled()
                try:
                    future.result()
                except Exception as exc:
                    logger.error("Page scan thread failed: %s", exc)
                    self._emit_log("error", f"Page scan thread failed: {exc}")
                with lock:
                    completed += 1
                progress = PAGE_PROGRESS_START + (completed / total) * (CORRELATE_PROGRESS - PAGE_PROGRESS_START)
                self._emit_progress(progress, f"Scanning pages... {completed}/{total}")
        finally:
            if executor is not None:
                executor.shutdown(wait=False, cancel_futures=True)

    def _generate_reports(self, scan_result, target) -> list:
        from core.reporter import Reporter

        paths = []
        self._emit_log("info", "Generating reports...")

        # The engine's strict validation can reject reports when scanners report
        # UNKNOWN-status findings (pre-existing CLI behaviour that silently drops
        # the report). The GUI keeps the engine untouched but surfaces validation
        # warnings in the live log and still produces the report.
        reporter = Reporter(branding=self.branding, strict_validation=False)
        if self.report_dir:
            os.makedirs(self.report_dir, exist_ok=True)
            reporter.report_dir = self.report_dir

        for warning in reporter.validate_results(scan_result):
            self._emit_log("warning", f"Report validation: {warning}")

        if self.outputs.get("html", True):
            try:
                html_path = reporter.generate_html(scan_result, target)
                if html_path and os.path.exists(html_path):
                    paths.append(html_path)
                    self._emit_log("info", f"HTML report: {html_path}")
                else:
                    self._emit_log("error", "HTML report generation failed")
            except Exception as exc:
                self._emit_log("error", f"HTML report failed: {exc}")

        if self.outputs.get("pdf"):
            try:
                from core.pdf_reporter import PDFReporter
                pdf_reporter = PDFReporter(branding=self.branding)
                if self.report_dir:
                    os.makedirs(self.report_dir, exist_ok=True)
                    pdf_reporter.report_dir = self.report_dir
                pdf_path = pdf_reporter.generate_pdf(scan_result, target)
                if pdf_path and os.path.exists(pdf_path):
                    paths.append(pdf_path)
                    self._emit_log("info", f"PDF report: {pdf_path}")
                else:
                    self._emit_log("warning", "PDF report unavailable (weasyprint not functional)")
            except Exception as exc:
                self._emit_log("warning", f"PDF report failed: {exc}")

        return paths

    def _build_summary(self, scan_result, report_paths, start_wall) -> dict:
        stats = scan_result.get_statistics()
        auth_stats = stats.get('auth') or {}

        # Phase A9: the GUI is presentation-only and never computes confidence.
        # The Assessment is the single owner of the scan-wide assessment_confidence.
        assessment = getattr(scan_result, "assessment", None)
        confidence = assessment.assessment_confidence if assessment is not None else 0

        findings_rows = []
        for finding in scan_result.findings:
            findings_rows.append({
                "module": finding.module or finding.module_name,
                "title": finding.title or finding.description or finding.reason or "",
                "status": finding.status.value if hasattr(finding.status, "value") else str(finding.status),
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                "confidence": finding.confidence,
                "reason": finding.reason or "",
                "target": finding.target or "",
            })

        return {
            "target": self.target,
            "mode": self.mode["label"],
            "mode_key": self.mode.get("label", ""),
            "started": datetime.now().isoformat(timespec="seconds"),
            "duration": stats.get("duration", time.monotonic() - start_wall),
            "stats": stats,
            "risk_score": stats.get("risk_score", 0),
            "overall_severity": stats.get("overall_severity", "No Risk"),
            "overall_description": stats.get("overall_description", ""),
            "overall_color": stats.get("overall_color", "#2196F3"),
            "overall_tier": stats.get("overall_tier", "none"),
            "confidence": confidence,
            "modules_completed": stats.get("coverage_executed", 0),
            "coverage": stats.get("coverage_percentage", 0),
            "vulnerabilities": stats.get("vulnerabilities", 0),
            "critical": stats.get("critical", 0),
            "high": stats.get("high", 0),
            "medium": stats.get("medium", 0),
            "low": stats.get("low", 0),
            "warnings": stats.get("warning", 0),
            "info": stats.get("info", 0),
            "safe": stats.get("safe", 0),
            "requests_sent": stats.get("requests_sent", 0),
            "pages_crawled": stats.get("pages_crawled", 0),
            "auth_mode": auth_stats.get("mode"),
            "auth_session_valid": auth_stats.get("session_valid"),
            "report_paths": list(report_paths),
            "scan_result": scan_result,
            "findings": findings_rows,
        }
