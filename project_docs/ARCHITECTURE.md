# SEA Corporate Security Scanner — Architecture

## Overview

The scanner is a modular Python-based web security assessment tool. It performs
crawling, host-level scans, page-level scans, and generates professional reports.

## Directory Structure

```
scanner_v4/
├── main.py                   # Entry point — SeaScanner orchestrator class
├── core/                     # Shared engine modules
│   ├── finding.py            # Finding, Severity, Status, ScanResult data models
│   ├── evidence.py           # Evidence dataclass, EvidenceBuilder, enums
│   ├── decision_engine.py    # Post-scan decision: severity, CVSS, CWE, impact
│   ├── crawler.py            # Web crawl + POST form extraction + JS-aware crawl
│   ├── browser.py            # Playwright BrowserManager (context pooling)
│   ├── js_crawler.py         # JSCrawler — JS link/form extraction, XHR capture, SPA detection
│   ├── reporter.py           # HTML + TXT report generation
│   ├── http_client.py        # TrackedSession + ResponseCache (LRU)
│   └── config.py             # ScanConfig dataclass
├── scanners/                 # Individual security scanners
│   ├── base.py               # BaseScanner abstract class + shared methods
│   ├── registry.py           # Central scanner registry (ALL/HOST/PAGE lists)
│   ├── sqli.py               # SQL Injection (error, time, boolean-based)
│   ├── xss.py                # Cross-Site Scripting (reflection-verified)
│   ├── headers.py            # Security headers audit
│   ├── tls.py                # TLS/SSL certificate analysis
│   ├── cookies.py            # Cookie security flags audit
│   ├── sensitive_files.py    # Sensitive file discovery
│   ├── cors.py               # CORS misconfiguration detection
│   ├── csrf.py               # CSRF token presence check
│   ├── lfi.py                # Local File Inclusion
│   ├── ssrf.py               # Server-Side Request Forgery
│   ├── http_methods.py       # Dangerous HTTP methods
│   ├── open_redirect.py      # Open redirect detection
│   ├── host_header.py        # Host header injection
│   ├── source_leaks.py       # Source code leakage patterns
│   ├── dns_scanner.py        # DNS record enumeration
│   ├── ports.py              # Common port scanning
│   ├── security_txt.py       # security.txt presence check
│   └── tech_detect.py        # Technology fingerprinting
├── project_docs/             # Documentation
├── reports/                  # Generated report output
└── logs/                     # Scan log files
```

## Scan Lifecycle

```
main() ─► SeaScanner.run()
              │
              ├─ show_banner()
              ├─ get_target()
              ├─ get_post_data()
              │    ├─ auto_extract_post_data()  ← Crawler.extract_post_forms()
              │    └─ get_post_data_manual()
              ├─ crawl_target()                 ← Crawler (HTTP or JSCrawler if JS mode)
              ├─ show_scan_info()
              ├─ run_scan_on_all_pages()
              │    ├─ run_host_scan()
              │    │    └─ host-level scanners (TLS, DNS, Ports, Headers, TechDetect, SecurityTxt)
              │    └─ run_page_scan() × pages (ThreadPoolExecutor, configurable workers)
              │         └─ page-level scanners (SQLi, XSS, LFI, Cookies, etc.)
              │              └─ scanner.run()
              │                   ├─ scanner.scan() → Finding
              │                   └─ DecisionEngine.decide(finding)
              ├─ show_summary()
              └─ generate_reports()
                   ├─ Reporter.generate_html()
                   └─ Reporter.generate_txt()
```

## Data Flow

1. **Scanner Base** (`BaseScanner`, `scanners/base.py`):
   - `__init__`: target, shared `TrackedSession`, post_data
   - `get_params()`, `inject_payload()`, `post_data_with_payload()` — shared by 5 scanners
   - `add_evidence_with_snippet()` — captures response body, headers, timing
   - `run()`: calls `scan()` → `DecisionEngine.decide(finding)`
   - Scanners override `scan()` to return a `Finding`

2. **Scanner Registry** (`scanners/registry.py`):
   - `ALL_SCANNERS` (18 scanners), `HOST_LEVEL_SCANNERS` (6), `PAGE_LEVEL_SCANNERS` (12)
   - Adding a scanner = 1 import + 1 list entry

3. **Configuration** (`core/config.py`):
   - `ScanConfig` dataclass: max_pages, max_workers, request_timeout, user_agent
   - `SeaScanner` accepts optional `config` parameter

4. **HTTP Client** (`core/http_client.py`):
   - `TrackedSession` — thread-safe request counter, shared connection pool
   - `ResponseCache` — LRU cache (200 entries, 60s TTL)

5. **Finding** (`core/finding.py`):
   - Central data object: module, status, severity, confidence, evidence, CVSS, CWE, impact
   - Weighted-average confidence scoring from evidence
   - `ScanResult` collects findings, provides statistics, risk score, validation

6. **Evidence** (`core/evidence.py`):
   - Dataclass with level, type, description, payload, raw_data (snippets, headers, timing)
   - `EvidenceBuilder` provides static factory methods for each level

7. **Decision Engine** (`core/decision_engine.py`):
   - Post-processes every finding: status, severity, exploitability, CWE, OWASP, impact, CVSS 3.1 vector
   - `SEVERITY_BY_MODULE` maps module names to base severity

8. **Crawler** (`core/crawler.py`):
   - Web crawl with duplicate detection (visited set), 49 skip extensions
   - `extract_post_forms()` — POST form extraction (merged from deleted form_crawler.py)
   - Constructor accepts `use_js` and `browser_manager` params
   - `crawl()` delegates to `JSCrawler` when JS mode is enabled and Playwright available

9. **Browser** (`core/browser.py`):
   - `BrowserManager` — Playwright lifecycle manager with context pooling
   - `start()` launches persistent Chromium in headless mode
   - `get_page()` round-robins across contexts; `close_page()` returns page to pool
   - `stop()` closes browser gracefully
   - `try/except` import pattern: `PLAYWRIGHT_AVAILABLE` flag, graceful fallback

10. **JSCrawler** (`core/js_crawler.py`):
    - `JSCrawler(crawl()` — entry point, mirrors `Crawler.crawl()` signature
    - Dynamic link extraction via `document.links` and `querySelectorAll('a')`
    - Dynamic form extraction and input enumeration
    - XHR/Fetch response interception via `page.on('response')`
    - JS variable extraction (window globals, meta tags, script elements)
    - SPA framework detection: Nuxt, Next.js, Vue, React, Angular
    - Content deduplication via MD5 hash of rendered HTML
    - `networkidle` wait strategy + configurable timeout

11. **Reporter** (`core/reporter.py`):
   - HTML report with embedded CSS, vulnerability sections, statistics
   - TXT report (aliased as generate_pdf for backward compat)

## Key Design Decisions

- **One shared `TrackedSession`** for all 18 scanners + crawler (was 19 separate pools)
- **Scanner Registry pattern** — loose coupling, easy to add/remove scanners
- **Multi-step verification** — all major scanners confirm signals before reporting
- **Weighted-average confidence** — more stable than sum accumulation
- **CVSS 3.1 vectors** generated for every finding
- **Response snippets + timing** in evidence raw_data for forensics
- **Logging** to `logs/` directory coexists with console output
- **Backward compat**: `generate_pdf()` redirects to `generate_txt()`
- **JS crawling opt-in**: `use_js_crawler=False` by default; existing HTTP crawler remains default
- **Playwright graceful degradation**: `try/except` import fallback when Playwright not installed
- **Browser context pooling**: up to `max_contexts` contexts for balanced usage; pages short-lived
- **SPA detection**: framework-specific globals (`__NUXT__`, `__NEXT_DATA__`, `angular`, etc.) rather than heuristic analysis

## Resolved Issues

- Session management: single shared `TrackedSession` (was 19 separate pools)
- Duplicated logic: `get_params()`, `inject_payload()` moved to `BaseScanner`
- Dead code: `classifier.py`, `fingerprinter.py`, `form_crawler.py` deleted
- Fake metrics: real request tracking via `TrackedSession.request_count`
- Logging: Python logging module added, coexists with console output
- Evidence comparison: enum-vs-string bug fixed in the confidence calculation (archived as `tests/v2_reference.v2_apply_evidence_assessment`)
- HTML escaping: `_escape_html` uses valid `&amp;`, `&lt;`, `&gt;`, `&quot;`
- SSRF detection: baseline comparison + metadata patterns + multi-IP verification
- XSS detection: reflection verification (two-phase) to reduce false positives
- SQLi detection: multi-step confirmation (error + time + boolean)
- CORS: trusted origin whitelist, OPTIONS pre-flight, tiered severity
- LFI: adaptive depth, error-based detection, multi-path confirmation
