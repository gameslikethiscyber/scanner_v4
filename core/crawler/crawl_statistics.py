"""
Crawl statistics (SOP v4.0 Phase 2 — Advanced Smart Crawling).

Collects per-crawl metrics exposed through ``crawl_statistics.diag`` — the
same dictionary the rest of the engine (``main.py``, GUI ``ScanWorker``) reads,
plus new Phase 2 counters for the attack-surface report.
"""

from __future__ import annotations

import time
from typing import Dict


class CrawlStatistics:
    def __init__(self):
        self.reset()

    def reset(self) -> None:
        t = time.time()
        self._start = t
        self._end = t
        self.pages_discovered = 0
        self.pages_scanned = 0
        self.pages_skipped = 0
        self.duplicates = 0
        self.redirects = 0
        self.redirect_loops = 0
        self.failed = 0
        self.errors = 0
        self.timeouts = 0
        self.urls_discovered = 0
        self.urls_scanned = 0
        self.urls_skipped_extension = 0
        self.urls_skipped_content_type = 0
        self.urls_skipped_status = 0
        self.urls_skipped_duplicate = 0
        self.urls_skipped_not_html = 0
        self.urls_skipped_timeout = 0
        self.urls_skipped_error = 0
        self.urls_skipped_out_of_scope = 0
        self.links_found_total = 0
        self.links_internal = 0
        self.links_external = 0
        self.links_skipped_extension = 0
        self.links_skipped_hash = 0
        self.pages_useful = 0
        self.pages_not_useful = 0
        self.forms_discovered = 0
        self.hidden_inputs_discovered = 0
        self.js_files = 0
        self.js_urls_discovered = 0
        self.sitemap_entries = 0
        self.robots_entries = 0
        self.sitemap_parsed = False
        self.robots_parsed = False
        self.classifications = {}
        self.avg_response_ms = 0.0
        self.duration_s = 0.0
        self._latencies = []

    # -- timing -----------------------------------------------------------
    def start(self) -> None:
        self._start = time.time()

    def finish(self) -> None:
        self._end = time.time()
        self.duration_s = self._end - self._start
        if self._latencies:
            self.avg_response_ms = round(sum(self._latencies) / len(self._latencies), 2)

    def record_latency(self, seconds: float) -> None:
        self._latencies.append(seconds * 1000.0)

    # -- convenience ------------------------------------------------------
    def skipped_total(self) -> int:
        return self.pages_skipped

    def to_diag(self) -> Dict:
        """Compatibility dictionary exported to callers."""
        total_skipped = sum([
            self.urls_skipped_extension,
            self.urls_skipped_content_type,
            self.urls_skipped_status,
            self.urls_skipped_duplicate,
            self.urls_skipped_not_html,
            self.urls_skipped_timeout,
            self.urls_skipped_error,
            self.urls_skipped_out_of_scope,
        ])
        return {
            "crawler_type": "http",
            "urls_visited": self.urls_scanned,
            "urls_discovered": self.urls_scanned + total_skipped,
            "urls_scanned": self.urls_scanned,
            "urls_skipped_extension": self.urls_skipped_extension,
            "urls_skipped_content_type": self.urls_skipped_content_type,
            "urls_skipped_status": self.urls_skipped_status,
            "urls_skipped_duplicate": self.urls_skipped_duplicate,
            "urls_skipped_not_html": self.urls_skipped_not_html,
            "urls_skipped_timeout": self.urls_skipped_timeout,
            "urls_skipped_error": self.urls_skipped_error,
            "urls_skipped_out_of_scope": self.urls_skipped_out_of_scope,
            "urls_skipped_total": total_skipped,
            "links_found_total": self.links_found_total,
            "links_internal": self.links_internal,
            "links_external": self.links_external,
            "links_skipped_extension": self.links_skipped_extension,
            "links_skipped_hash": self.links_skipped_hash,
            "pages_useful": self.pages_useful,
            "pages_not_useful": self.pages_not_useful,
            "forms_discovered": self.forms_discovered,
            "hidden_inputs_discovered": self.hidden_inputs_discovered,
            "js_files": self.js_files,
            "js_urls_discovered": self.js_urls_discovered,
            "sitemap_entries": self.sitemap_entries,
            "robots_entries": self.robots_entries,
            "sitemap_parsed": self.sitemap_parsed,
            "robots_parsed": self.robots_parsed,
            "duplicates": self.duplicates,
            "redirects": self.redirects,
            "redirect_loops": self.redirect_loops,
            "failed": self.failed,
            "avg_response_ms": self.avg_response_ms,
            "crawl_duration_s": self.duration_s,
            "classifications": dict(self.classifications),
        }