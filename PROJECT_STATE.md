# Project State

## Project Overview
- **Project Name**: SEA Corporate Security Scanner
- **Current Version**: 1.8.0 (Report Format: 3.1)
- **Main Purpose**: Modular Python-based web security assessment tool that performs crawling, host-level scans, page-level scans, and generates professional security reports with transparent risk scoring, CWE/OWASP/CVSS mapping, and commercial-grade presentation.

## Current Architecture

### Folder Structure
```
scanner_v4/
├── main.py                   # Entry point — SeaScanner orchestrator class
├── PROJECT_STATE.md          # This file — single source of truth for continuity
├── test_validation.py        # 160+ validation checks (must pass after every change)
├── requirements.txt          # Dependencies (requests, rich, dnspython, bs4, cryptography, playwright optional)
├── core/                     # Shared engine modules
│   ├── finding.py            # Finding, Severity, Status, ScanResult data models (v3.1)
│   ├── evidence.py           # Evidence dataclass, EvidenceBuilder, EvidenceLevel/Type enums
│   ├── decision_engine.py    # DecisionEngine v4.0 + RiskCalculator + Standards mapping
│   ├── reporter.py           # HTML/TXT/JSON/Markdown/CSV report generation with branding
│   ├── crawler.py            # HTTP web crawl + POST form extraction
│   ├── browser.py            # Playwright BrowserManager (context pooling, graceful fallback)
│   ├── js_crawler.py         # JSCrawler — JS link/form extraction, XHR capture, SPA detection
│   ├── http_client.py        # TrackedSession + ResponseCache (LRU, 200 entries, 60s TTL)
│   └── config.py             # ScanConfig dataclass with branding fields
├── scanners/                 # 18 individual security scanners
│   ├── base.py               # BaseScanner abstract class + shared methods
│   ├── registry.py           # Central scanner registry (ALL_SCANNERS / HOST_LEVEL / PAGE_LEVEL)
│   ├── sqli.py               # SQL Injection (error, time, boolean-based, multi-step verify)
│   ├── xss.py                # Cross-Site Scripting (reflection-verified, two-phase)
│   ├── headers.py            # Security headers audit
│   ├── tls.py                # TLS/SSL certificate analysis
│   ├── cookies.py            # Cookie security flags audit
│   ├── sensitive_files.py    # Sensitive file discovery (host-level, 13 checks)
│   ├── cors.py               # CORS misconfiguration detection (OPTIONS pre-flight)
│   ├── csrf.py               # CSRF token presence check
│   ├── lfi.py                # Local File Inclusion (adaptive depth, error-based)
│   ├── ssrf.py               # Server-Side Request Forgery (multi-IP confirm)
│   ├── http_methods.py       # Dangerous HTTP methods
│   ├── open_redirect.py      # Open redirect detection
│   ├── host_header.py        # Host header injection (4 test hosts, FP-reduced)
│   ├── source_leaks.py       # Source code leakage patterns (14 specific indicators)
│   ├── dns_scanner.py        # DNS record enumeration
│   ├── ports.py              # Common port scanning
│   ├── security_txt.py       # security.txt presence check
│   └── tech_detect.py        # Technology fingerprinting
├── payloads/                 # Payload data files
├── project_docs/             # Documentation (development_progress.txt, CHANGELOG, ARCHITECTURE, DECISIONS, BUGS, TODO)
├── reports/                  # Generated report output (gitignored)
├── logs/                     # Scan log files (gitignored)
└── templates/                # Report templates
```

### Core Classes
| Class | File | Purpose |
|-------|------|---------|
| `SeaScanner` | `main.py:52` | Orchestrator — crawl, scan, report pipeline |
| `ScanConfig` | `core/config.py:9` | Configuration dataclass (crawl, JS, parallelism, branding) |
| `TrackedSession` | `core/http_client.py` | Shared HTTP session with request counter |
| `ResponseCache` | `core/http_client.py` | LRU cache (200 entries, 60s TTL) |
| `Crawler` | `core/crawler.py` | HTTP web crawler with 49 skip extensions |
| `BrowserManager` | `core/browser.py` | Playwright lifecycle manager + context pooling |
| `JSCrawler` | `core/js_crawler.py` | JavaScript-aware crawling (SPA, XHR, dynamic forms) |
| `BaseScanner` | `scanners/base.py:13` | Abstract scanner with shared methods |
| `Finding` | `core/finding.py:37` | Central finding data object |
| `ScanResult` | `core/finding.py:301` | Findings collection + statistics + risk score |
| `DecisionEngine` | `core/decision_engine.py:9` | Post-processing: status, severity, CVSS, CWE, standards, verify commands |
| `RiskCalculator` | `core/decision_engine.py:457` | Weighted risk score + security letter grade |
| `EvidenceBuilder` | `core/evidence.py` | Factory for Evidence dataclass at various levels |
| `Reporter` | `core/reporter.py:11` | HTML/TXT/JSON/MD/CSV report generation with branding |

### Important Files
- `main.py` — Entry point, scan lifecycle orchestration, format selection menu
- `core/finding.py` — Data models, deduplication, verification status, confidence calculation, `to_dict()`
- `core/decision_engine.py` — Standards mapping (all 18 scanners), CVSS 3.1 vectors, security grade, verify commands, replay data
- `core/reporter.py` — Complete HTML template with attack surface, timeline, collapsible evidence, verification badges, dark mode, print CSS, branding, replay
- `scanners/registry.py` — `ALL_SCANNERS` (18), `HOST_LEVEL_SCANNERS` (7), `PAGE_LEVEL_SCANNERS` (11)
- `test_validation.py` — 160+ checks, must pass after every change
- `project_docs/development_progress.txt` — SSOT for development progress

## Completed Features

- [x] **18 Security Scanners**: SQLi, XSS, SSRF, LFI, Host Header, Open Redirect, CSRF, CORS, HTTP Methods, Headers, Cookies, TLS, DNS, Open Ports, Security.txt, Source Code Leaks, Tech Detection, Sensitive Files
- [x] **Scanner Registry**: Centralised ALL/HOST/PAGE lists, loose coupling
- [x] **Shared HTTP Session**: Single `TrackedSession` (was 19 separate pools)
- [x] **Response Cache**: LRU cache (200 entries, 60s TTL)
- [x] **Multi-step Verification**: All major scanners confirm before reporting (SQLi, XSS, SSRF, LFI)
- [x] **Weighted-average Confidence Scoring**: Base=50, evidence-driven
- [x] **CVSS 3.1 Vectors**: Per-finding vector string with explanation
- [x] **Standards Mapping**: CWE, OWASP Top 10, CAPEC, MITRE ATT&CK, OWASP ASVS (all 18 scanners)
- [x] **Security Letter Grade**: A+ through F alongside risk score
- [x] **Smart Recommendations**: Per-scanner recommendations with config examples and code snippets
- [x] **Verify Commands**: Auto-generated curl, Burp, browser, ZAP verification steps per finding
- [x] **Replay Data**: Request/response evidence stored in `replay_data`, displayed in reports with copy-to-clipboard
- [x] **Host-level Scans Always Run**: Before page scan; base URL fallback if 0 useful pages
- [x] **Finding Deduplication**: By module + evidence (FAIL/WARNING) or by module alone (PASS)
- [x] **Verification Status**: verified/likely/possible/manual_review/unverified derived from evidence level
- [x] **HTTP Request/Response Evidence**: `EvidenceType.REQUEST_RESPONSE`, `capture_http_evidence()`
- [x] **Transparent Risk Score**: Weighted formula (severity x confidence x verification x occurrences) with breakdown table
- [x] **Professional HTML Reports**: Executive summary, attack surface, risk breakdown, timeline, collapsible evidence, verification badges, dark mode, print CSS
- [x] **Export Formats**: HTML, JSON, Markdown, CSV, TXT with format selection menu
- [x] **Report Branding**: Custom logo, company name, consultant name, client name, report ID
- [x] **Detection Replay**: Curl commands with copy-to-clipboard button in finding cards
- [x] **Browser Context Pooling**: Up to `max_contexts` contexts, `get_page()` round-robin
- [x] **SPA Detection**: Nuxt, Next.js, Vue, React, Angular framework detection
- [x] **JS Crawling**: Dynamic link/form extraction, XHR/Fetch interception, networkidle wait
- [x] **Playwright Graceful Degradation**: `try/except` import fallback
- [x] **Configuration System**: `ScanConfig` dataclass
- [x] **Logging**: Python logging to `logs/` directory, coexists with console output
- [x] **Attack Surface Metrics**: 20+ fields populated from real crawler diagnostics
- [x] **PASS Deduplication**: By module name, aggregated via `aggregate_safe_findings()`
- [x] **Executive Summary**: Smart contextual summary from actual scan data
- [x] **Coverage Skip Reasons**: Per-reason display with module names
- [x] **Finding Timeline**: Visual pipeline in every finding card
- [x] **Validation Suite**: 160+ checks, 0 errors, 0 warnings

## Features In Progress
- (none — awaiting direction)

## Remaining Tasks

### High Priority
1. **Advanced Parameter Discovery**: Fuzz parameter names from wordlist, discover hidden GET/POST parameters, detect parameter-based vulnerabilities via parameter brute-force
2. **DOM-based XSS Detection**: PostMessage sink analysis, DOM taint tracking, sink-source correlation

### Medium Priority
3. Update `test_validation.py` with tests for branding (company name, report ID, logo URL in HTML) and replay (replay_data in to_dict, verify_commands in HTML)
4. Update `scanner_version` in `finding.py` `get_statistics()` after each feature release

### Low Priority / Long-term
5. Async support (asyncio + aiohttp) for single-process concurrency
6. Plugin system for third-party scanners (defined API contract)
7. Configuration file (YAML/JSON) instead of hardcoded settings
8. Real PDF generation (ReportLab or WeasyPrint)
9. Docker containerization
10. CI/CD pipeline with automated testing
11. Soft-404 detection in crawler
12. Host header override test (needs low-level HTTP client)
13. ResponseCache integration into TrackedSession

## Current Problems

### Known Bugs
| ID | Issue | File | Priority |
|----|-------|------|----------|
| B9 | `ScanResult.add_finding()` not thread-safe | `core/finding.py` | Low |
| B12 | Missing requirements degrade functionality (cryptography, bs4, rich) | `requirements.txt` | Low |
| B13 | Scanner instance mutable attributes shared across threads | All scanners | Low |

### Technical Debt
- 33 Python source files, ~5,200 lines
- `project_docs/README.md` is outdated (references deleted files)
- `project_docs/development_progress.txt` and `PROJECT_STATE.md` should be kept in sync
- Some docstrings are still in Arabic (should be English)
- No type hints in some scanner files
- `generate_txt()` still uses Arabic comments and emoji

## Decisions Made

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | Work incrementally, never rewrite entire project | Minimizes risk, maintains backward compatibility |
| D2 | `project_docs/development_progress.txt` is SSOT | Enables session recovery |
| D3 | Fix enum-vs-string comparison first | Affects ALL findings' confidence scoring |
| D4 | Delete unused Classifier/Fingerprinter classes | Dead code increases maintenance burden |
| D5 | Shared session in Phase 2 (not Phase 1) | Phase 1 focuses on bugs; session sharing is optimization |
| D6 | Scanner Registry pattern | Adding scanner = 1 import + 1 list entry |
| D7 | Weighted-average confidence scoring (base=50) | More stable and predictable |
| D8 | Multi-step verification for detection quality | Dramatically reduces false positives |
| D9 | Thread safety deferred to Phase 5 | Requires coordinated changes to main.py run loop |
| D10 | Single shared `TrackedSession` for all scanners + crawler | Was 19 separate connection pools |
| D11 | CVSS 3.1 vectors generated for every finding | Industry standard for severity communication |
| D12 | Response snippets + timing in evidence raw_data | Better forensics and reproducibility |
| D13 | Backward compat: `generate_pdf()` → `generate_txt()` | Avoid breaking existing integrations |
| D14 | JS crawling opt-in (`use_js_crawler=False` default) | HTTP crawler is sufficient for most targets |
| D15 | Playwright graceful degradation via `try/except` | No hard dependency on Playwright |
| D16 | Browser context pooling (max_contexts, round-robin) | Balanced resource usage, pages are short-lived |
| D17 | SPA detection via framework-specific globals | More reliable than heuristic analysis |
| D18 | **No feature bloat**: reject Items 1, 5, 6, 7, 8, 9, 10, 14, 15, 16, 18, 19, 20 | Keep scanner focused, high-quality, low-maintenance |
| D19 | Selected 7 high-impact/low-effort items from 20-item list | Verify commands, CWE mapping, rich CVSS, security grade, smart recommendations, report branding, detection replay |
| D20 | Decision engine v4.0 uses single `STANDARDS` dict | Clean standards mapping for all 18 modules |
| D21 | `PROJECT_STATE.md` is the root-level continuity file | Ensures AI agents can resume seamlessly after interruption |

## Dependencies

### Required
| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28.0 | HTTP client |
| `rich` | >=13.0.0 | Beautiful console output (graceful fallback) |
| `dnspython` | >=2.4.0 | DNS lookups |
| `beautifulsoup4` | >=4.11.0 | HTML parsing, crawling (graceful fallback) |
| `cryptography` | >=42.0.0 | TLS certificate analysis (graceful fallback) |

### Optional
| Library | Version | Purpose |
|---------|---------|---------|
| `playwright` | >=1.40.0 | JavaScript-aware crawling (must also run `playwright install chromium`) |

### Runtime
- Playwright v1.61.0 + Chromium installed
- Python 3.10+ recommended (f-string compatibility)

## Recent Changes

### v1.8.0 — 2026-07-28 — Report Branding & Detection Replay
- **Added**: Report branding — custom `logo_url`, `company_name`, `consultant_name`, `client_name`, `report_id` in HTML header/footer via `ScanConfig.branding`
- **Added**: Detection replay — curl commands with copy-to-clipboard button in every finding card; `replay_data` auto-populated from evidence raw_data
- **Modified**: `core/reporter.py` — Branding support, replay section, copy-to-clipboard JS
- **Modified**: `core/decision_engine.py` — `_populate_replay_data()` in decide() pipeline
- **Modified**: `core/config.py` — Branding fields + `get_branding()` method
- **Modified**: `core/finding.py` — Scanner version 1.8.0, report version 3.1
- **Modified**: `main.py` — Passes `config.get_branding()` to Reporter
- **Validation**: 160+ checks pass (0 errors, 0 warnings)

### v1.7.0 — 2026-07-28 — Final Polish (CodeCanyon Readiness)
- Attack surface metrics, PASS dedup, executive summary, coverage skip reasons, finding timeline, collapsible HTTP evidence, verification badges, dark mode, print CSS, JSON/MD/CSV exports

### v1.6.0 — 2026-07-28 — Production Quality Audit
- Host header FP fix, deduplication, risk score rewrite, HTTP evidence, dynamic confidence/verification levels, report overhaul, 21 new validation checks

### v1.4.0 — 2026-07-28 — Phase 4+5 Combined
- Multi-step verification, CVSS 3.1 vectors, scanner registry, thread safety, config system, logging, dead code removal

### v1.3.0 — 2026-07-28 — Phase 4 Detection Quality
- Multi-step SQLi/XSS/SSRF/LFI, CORS trusted origins, adaptive LFI depth, weighted-average confidence

### v1.2.0 — 2026-07-27 — Phase 3 Architecture
- Scanner Registry, Config System, Logging, dead code removal

### v1.1.0 — 2026-07-27 — Phase 2 Performance
- Shared session, response cache, optimized crawler

### v1.0.1 — 2026-07-27 — Phase 1 Bug Fixes
- Evidence comparison, HTML escaping, SSFP/XSS/LFI/cookie fixes

### v1.0.0 — 2026-07-27 — Initial

## Next Recommended Task

**Option A**: Start **Feature 2 — Advanced Parameter Discovery**: Fuzz parameter names from wordlist, discover hidden GET/POST parameters, detect parameter-based vulnerabilities via parameter brute-force. Requires a wordlist and new scanner module.

**Option B**: Start **Feature 3 — DOM-based XSS Detection**: PostMessage sink analysis, DOM taint tracking, sink-source correlation. Requires integration with JSCrawler.

**Option C**: Production testing against real targets to validate scanner stability and accuracy before CodeCanyon packaging.

## Important Notes

### For AI Agents Continuing This Session

1. **ALWAYS start by reading** `PROJECT_STATE.md` (this file), `project_docs/development_progress.txt`, and `project_docs/CHANGELOG.md` to understand current state.

2. **Never rewrite entire files** — work incrementally, one phase/feature at a time.

3. **Run `python test_validation.py` after every change** — all 160+ checks must pass (0 errors, 0 warnings).

4. **Update `PROJECT_STATE.md` after every major implementation** — append new progress, never overwrite useful information.

5. **Two SSOT files exist**: `project_docs/development_progress.txt` (original) and `PROJECT_STATE.md` (root-level). Keep both in sync.

6. **Playwright is installed** (v1.61.0 + Chromium) but opt-in only via `use_js_crawler=True`.

7. **Host-level scanners always run** before page-level scanners. Base URL fallback exists for 0 useful pages.

8. **Decision engine v4.0** has all 18 scanners mapped with CWE, OWASP, CAPEC, MITRE, ASVS, severity, impact, CVSS, verify commands, and replay data.

9. **The scanner version** is in `core/finding.py` `get_statistics()` — bump it with every release.

10. **Backward compatibility is mandatory** — never remove or rename public methods/classes without aliasing.

11. **No feature bloat** — reject any feature that doesn't increase detection accuracy, user trust, or commercial quality.

12. **Emoji-free English-only** output in reports. Console output may still use emoji for Rich visual formatting.
