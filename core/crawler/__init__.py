"""
Advanced smart crawling engine (SOP v4.0 Phase 2).

This package replaces the legacy single-module ``core/crawler.py`` with a
dedicated, modular subsystem while keeping the public ``Crawler`` API and
diagnostics fully backward compatible (callers in ``main.py``, the GUI
``ScanWorker`` and the tests import ``from core.crawler import Crawler``).
"""

from core.crawler.crawler import Crawler
from core.crawler.queue import CrawlQueue
from core.crawler.scope_manager import ScopeManager
from core.crawler.robots_parser import Robots, RobotsParser
from core.crawler.sitemap_parser import SitemapParser
from core.crawler.link_discovery import LinkDiscovery
from core.crawler.url_normalizer import URLNormalizer, normalize_url
from core.crawler.page_classifier import PageClassifier
from core.crawler.deduplicator import Deduplicator
from core.crawler.crawl_statistics import CrawlStatistics

__all__ = [
    "Crawler",
    "CrawlQueue",
    "ScopeManager",
    "Robots",
    "RobotsParser",
    "SitemapParser",
    "LinkDiscovery",
    "URLNormalizer",
    "normalize_url",
    "PageClassifier",
    "Deduplicator",
    "CrawlStatistics",
]