# Project State

## Project Overview
- **Project Name**: SEA Corporate Security Scanner
- **Current Version**: 4.13.1 (Report Format: 3.2)
- **Release Status**: Assessment Engine **feature-complete & stable** (engine logic frozen); professional HTML report redesign completed (v4.12.1), **professional GUI redesign completed** (v4.13.0, approved), and **final UI polish & usability review completed** (v4.13.1, approved) — presentation-only. Next: **Final Release Preparation** — Packaging & Distribution, Website, Gumroad, marketing assets, v5.0 release candidate. No architectural/engine changes unless a verified defect is found.
- **Main Purpose**: Modular Python-based web security assessment tool that performs crawling, host-level scans, page-level scans, and generates professional security reports with transparent risk scoring, CWE/OWASP/CVSS mapping, and commercial-grade presentation.

## Current Architecture

### Folder Structure
```
scanner_v4/
├── main.py                   # Entry point — SeaScanner orchestrator class
├── sea.py                    # Automation CLI — optional auth (--cookies/--bearer/--jwt/--header) [NEW v3.9.0]
├── gui/                      # PySide6 desktop GUI (presentation layer)
│   ├── app.py                # QApplication bootstrap + theme
│   ├── main_window.py        # Left icon rail, top bar, page stack, status bar, toast host
│   ├── version.py            # App identity / version source of truth
│   ├── controllers/          # ScanController — QThread lifecycle + event bridge
│   ├── pages/                # Overview, Scanner, History, Settings, About
│   ├── services/             # Settings/History (JSON), ScanWorker, log bridge
│   ├── widgets/              # LogView, KPI/Panel cards, controls, brand, risk meter, toast, summary
│   └── resources/            # QSS design system (dark/light/system), programmatic stroke icons
├── PROJECT_STATE.md          # This file — single source of truth for continuity
├── test_validation.py        # 160+ validation checks (must pass after every change)
├── requirements.txt          # Dependencies (requests, rich, dnspython, bs4, cryptography, playwright optional)
├── core/                     # Shared engine modules
│   ├── finding.py            # Finding, Severity, Status, ScanResult data models (v3.2)
│   ├── evidence.py           # Evidence dataclass, EvidenceBuilder, EvidenceLevel/Type enums (v2: 6 new types, verification metadata)
│   ├── decision_engine.py    # DecisionEngine v4.0 + RiskCalculator + Standards mapping
│   ├── verification_engine.py # Multi-pass verification engine (reflection, timing, status anomaly) [NEW v2.0.0]
│   ├── response_analyzer.py  # Centralized response analysis, security headers, cookies, tech detection, normalization [NEW v2.0.0]
│   ├── correlation_engine.py # Cross-finding correlation with 10 rules, confidence boost, severity escalation [NEW v2.0.0]
│   ├── reporter.py           # HTML/TXT/JSON/Markdown/CSV report generation with branding
│   ├── reporter.py           # HTML/TXT/JSON/Markdown/CSV report generation with branding
│   ├── crawler/              # Advanced smart crawling subsystem (SOP v4.0 Phase 2) [NEW v3.10.0]
│   │   ├── crawler.py       # Crawler orchestrator — bounded BFS engine (backward-compatible API)
│   │   ├── queue.py         #   BFS queue + depth limits (CrawlQueue)
│   │   ├── scope_manager.py #   ScopeManager — domain/subdomain/path/all + include/exclude patterns
│   │   ├── robots_parser.py #   robots.txt download + parse (sitemap refs, allowed/disallowed)
│   │   ├── sitemap_parser.py#   sitemap.xml / index / gzip parsing
│   │   ├── link_discovery.py#   anchors, nav, forms, canonical, meta-redirect, static JS URLs
│   │   ├── url_normalizer.py#   URLNormalizer — fragments, slashes, tracking params, default ports
│   │   ├── page_classifier.py#  PageClassifier — Login/Admin/API/Home/Error/First categories
│   │   ├── deduplicator.py #   URL + redirect + content-hash de-duplication
│   │   ├── crawl_statistics.py # counts/diag (legacy + Phase 2 keys)
│   │   └── forms_helper.py #   POST form extraction (shared legacy behaviour)
│   ├── browser.py            # Playwright BrowserManager (context pooling, graceful fallback)
│   ├── js_crawler.py         # JSCrawler — JS link/form extraction, XHR capture, SPA detection
│   ├── http_client.py        # TrackedSession + ResponseCache (LRU, 200 entries, 60s TTL)
│   ├── auth/                 # Optional authentication providers (SOP v4.0 Phase 1) [NEW v3.9.0]
│   │   ├── base.py           # AuthSpec (single input contract) + BaseProvider
│   │   ├── cookie_provider.py / bearer_provider.py / jwt_provider.py / header_provider.py
│   │   ├── session_validator.py  # SessionValidationResult + SessionValidator (probes fresh session)
│   │   ├── authentication_manager.py  # AuthenticationManager facade (build/apply/validate/mark_invalid)
│   │   └── __init__.py       # Facade re-exporting core.auth_manager API
│   └── config.py             # ScanConfig dataclass with branding fields + auth fields
├── scanners/                 # 18 individual security scanners
│   ├── base.py               # BaseScanner abstract class + SmartPayloadSystem, verification/response analyzer integration [v2]
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
└── templates/                # Report templates (Jinja2: report.html.j2)
```

### Core Classes
| Class | File | Purpose |
|-------|------|---------|
| `SeaScanner` | `main.py:52` | Orchestrator — crawl, scan, report pipeline |
| `ScanConfig` | `core/config.py:9` | Configuration dataclass (crawl, JS, parallelism, branding) |
| `TrackedSession` | `core/http_client.py` | Shared HTTP session with request counter |
| `ResponseCache` | `core/http_client.py` | LRU cache (200 entries, 60s TTL) |
| `Crawler` | `core/crawler/crawler.py` | Advanced smart BFS crawler — scope/depth/duration limits, robots+sitemap discovery, URL/redirect/content dedup, page classification (backward-compatible API, 49 skip extensions) |
| `BrowserManager` | `core/browser.py` | Playwright lifecycle manager + context pooling |
| `JSCrawler` | `core/js_crawler.py` | JavaScript-aware crawling (SPA, XHR, dynamic forms) |
| `BaseScanner` | `scanners/base.py` | Abstract scanner + SmartPayloadSystem, verification/response analyzer integration |
| `SmartPayloadSystem` | `scanners/base.py:14` | Adaptive payload selection by technology/param type, multi-encoding support |
| `Finding` | `core/finding.py:37` | Central finding data object (v3.2: correlation, verification, payload fields) |
| `ScanResult` | `core/finding.py:301` | Findings collection + statistics + risk score + correlation |
| `DecisionEngine` | `core/decision_engine.py:9` | Post-processing: status, severity, CVSS, CWE, standards, verify commands |
| `RiskCalculator` | `core/decision_engine.py:457` | Weighted risk score + security letter grade |
| `EvidenceBuilder` | `core/evidence.py` | Factory for Evidence dataclass at various levels (12+ builder methods) |
| `VerificationEngine` | `core/verification_engine.py` | Multi-pass verification (initial/confirmation/cross-validation/behavioral), reflection/timing/status checks |
| `ResponseAnalyzer` | `core/response_analyzer.py` | Response analysis, security headers, cookies, 16+ tech patterns, body normalization, similarity, sensitive patterns |
| `CorrelationEngine` | `core/correlation_engine.py` | 10 correlation rules, confidence boosting, severity escalation, correlation summary |
| `Reporter` | `core/reporter.py:11` | HTML/TXT/JSON/MD/CSV report generation with branding |

### Important Files
- `main.py` — Entry point, scan lifecycle orchestration, format selection menu
- `core/finding.py` — Data models, deduplication, verification status, confidence calculation, `to_dict()`
- `core/decision_engine.py` — Standards mapping (all 18 scanners), CVSS 3.1 vectors, security grade, verify commands, replay data
- `core/reporter.py` — Complete HTML template with attack surface, timeline, collapsible evidence, verification badges, dark mode, print CSS, branding, replay
- `scanners/registry.py` — `ALL_SCANNERS` (18), `HOST_LEVEL_SCANNERS` (7), `PAGE_LEVEL_SCANNERS` (11)
- `core/verification_engine.py` — Multi-pass verification: `VerificationEngine.verify_with_retry()`, `run_multi_pass()`, `check_reflection()`, `check_timing_delay()`, `check_status_code_anomaly()`
- `core/response_analyzer.py` — Centralized response analysis: `ResponseAnalyzer.analyze_response()`, `normalize_body()`, `body_similarity()`, `extract_sensitive_patterns()`, security header validation, cookie analysis, technology detection (16+ patterns)
- `core/correlation_engine.py` — Cross-finding correlation: 10 rules (xss_csp_bypass, cors_xss, cookie_hsts, etc.), confidence boost, severity escalation, correlation summary
- `test_validation.py` — 200+ checks, must pass after every change
- `project_docs/development_progress.txt` — SSOT for development progress

## Completed Features

- [x] **19 Security Scanners**: SQLi, XSS, SSRF, LFI, Host Header, Open Redirect, CSRF, CORS, HTTP Methods, Headers, Cookies, TLS, DNS, Open Ports, Security.txt, Source Code Leaks, Tech Detection, Sensitive Files, SSTI
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
- [x] **Multi-pass Verification Engine**: 4-pass (initial/confirmation/cross-validation/behavioral), reflection/timing/status anomaly checks, evidence building from verification results
- [x] **Response Analyzer**: Security header validation (10 headers), cookie analysis (Secure/HttpOnly/SameSite), technology detection (16+ patterns), body normalization, Jaccard similarity, sensitive pattern extraction (API keys, AWS, JWT, passwords, secrets)
- [x] **Correlation Engine**: 10 cross-finding rules, confidence boosting (5-20 pts), severity escalation, correlation summary for reporting
- [x] **Smart Payload System**: Adaptive payload selection by detected technology and param type, 5 encoding modes (url, double_url, unicode, hex, base64)
- [x] **Enhanced Evidence System**: 6 new EvidenceType values (BEHAVIOR_CHANGE, DOM_CHANGE, CONTENT_REFLECTION, SERVER_BEHAVIOR, CROSS_VALIDATION, CONSISTENCY_CHECK), 7 new builder methods, verification metadata tracking
- [x] **Enhanced Finding Data Model**: correlation_escalated, verification_passes, payload_evidence, response_fingerprint, baseline_fingerprint, technical_explanation, owasp_mapping, cwe_mapping, remediation_steps
- [x] **Enhanced Confidence Scoring**: Rewards multi-pass verification (+15), cross-validation (+10), and correlation (+5-20)
- [x] **All 18 Scanners Updated**: Multi-pass verification, smarter payloads, better evidence capture, response analysis integration
- [x] **Correlation in Main Pipeline**: Runs after all scanners complete, mutates findings with confidence/severity boosts
- [x] **Jinja2 HTML Templates**: Report skeleton extracted to `templates/report.html.j2`, editable without touching Python code
- [x] **Thread Safety (B9/B13)**: `ScanResult.add_finding()` protected by `threading.Lock()`, no mutable class-level state across all 18 scanners
- [x] **SOP Document**: `project_docs/SOP.md` — standard operating procedure for the project

## Features In Progress
- **Engine logic is FROZEN** (SOP v4.0 Phase 4 COMPLETE — Assessment Engine stable, v4.12.0). New engine features are not introduced unless they fix a verified defect. Development priority is **release quality**.
- **(A9 — Assessment Orchestrator Integration — **COMPLETE**)**
- **Professional GUI redesign (v4.13.0) — COMPLETE & APPROVED.**
- **Final Release Preparation — In progress**: UI polish, usability review, bug fixing, website, Gumroad, marketing assets (screenshots, demo video, banners), release checklist, packaging/distribution, v5.0 release candidate.

## Remaining Tasks

> **Scope note**: Engine logic is frozen (v4.12.0). No new engine features are
> introduced unless they fix a verified defect. Priority is **Final Release
> Preparation** (release quality only, then stop).

### High Priority (Final Release Preparation — current focus)
1. **Final UI polish**: review screenshots (`reports/screenshots/gui/*.png`), refine spacing/typography/layout details, ensure dark & light parity across all pages.
2. **Final usability review**: walk the full scan workflow (setup → running → completed), error handling, empty states, first-run onboarding.
3. **Final bug fixing**: any verified defect found during release QA (no engine changes unless verified defect).
4. **Website updates**: public-facing product site / landing pages.
5. **Gumroad preparation**: product page, pricing, license, EU/global sales config.
6. **Marketing assets**: screenshots, demo video, banners (social/Gumroad).
7. **Release checklist**: document & execute a formal go-live checklist.
8. **Packaging & distribution**: Windows executable (.exe) build/tooling, dependency freeze, checksums.
9. **v5.0 release candidate**: final candidate + release notes.

### Medium Priority (release quality supporting)
- Pdf report redesign is deferred (PDF output already functional; not on the v5.0 critical path unless requested).
- Update `test_validation.py` with tests for branding and replay as part of release QA (if time-boxed in the release cycle).

### Low Priority / Long-term (deferred — only with explicit approval)
10. **Engine additions (defect-fix only)**: Advanced Parameter Discovery, DOM-based XSS Detection
11. Async support (asyncio + aiohttp) for single-process concurrency
12. Plugin system for third-party scanners (defined API contract)
13. Configuration file (YAML/JSON) instead of hardcoded settings
14. Docker containerization
15. CI/CD pipeline with automated testing
16. Soft-404 detection in crawler
17. Host header override test (needs low-level HTTP client)
18. ResponseCache integration into TrackedSession

## Current Problems

### Known Bugs
| ID | Issue | File | Priority |
|----|-------|------|----------|
| B12 | Missing requirements degrade functionality (cryptography, bs4, rich) | `requirements.txt` | Low |

### Fixed Bugs (v2.0.1)
| ID | Issue | File | Fix |
|----|-------|------|-----|
| B9 | `ScanResult.add_finding()` not thread-safe | `core/finding.py` | Added `threading.Lock()` — already present in code, verified with 50-thread regression test |
| B13 | Scanner instance mutable attributes shared across threads | All scanners | Confirmed scanners create fresh instances per call, no class-level mutable state. Regression test covers all 18 scanners |

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
| D22 | **Engine logic FROZEN at v4.12.0** — no new engine features unless they fix a verified defect | Assessment Engine is pipeline-complete and stable (PARITY/REGRESSION/validation/engine all green); roadmap shifts to product quality |
| D23 | **GUI redesign uses a single shared design system** (indigo accent + report-aligned severity scale) mirrored from the HTML report | Desktop and report share one visual language; palette threading via `apply_palette` keeps dark/light consistent |
| D24 | **v4.13.0 = Professional GUI Redesign**; v4.12.1 = HTML report redesign (sequential, no duplicate version numbers) | Clean version history; GUI approved, then Final Release Preparation begins |

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

### v4.13.0 — 2026-08-03 — Professional GUI Redesign (presentation-only)
- **Desktop GUI redesigned to a commercial-grade design system** matching the HTML report's visual language: indigo accent `#4F46E5`, report-aligned severity scale (`#E5484D`/`#F76B15`/`#F5A623`/`#2E9E5B`/`#0E9F6E`), full dark + light palettes, complete QSS rewrite in `gui/resources/styles.py` (objectName selectors for every component).
- **Palette architecture threaded through every widget/page**: KPI cards, risk meter, summary, brand header, rail navigation icons (idle `subtext` / active `accent`), log views, toggles, toasts.
- **Bug fixes**: `summary._status_color` hardcoded `DARK` (now palette-aware); overview risk meter + settings toggles never received the palette; scanner log views; duplicate auth token page in `scanner_page.py`.
- **Removed dead code** `gui/pages/scan_page.py` (393 lines, no live imports).
- **`tools/gui_visuals.py`**: headless smoke + screenshot harness (offscreen platform, seeded throwaway history, palette-propagation assertions, all pages dark+light → `reports/screenshots/gui/`).
- **GUI redesign approved.** Gates: validation 0/0, engine 0/0, `REGRESSION=0` (PASS=10, WARNING=6), `PARITY=0`.
- **Next**: Final Release Preparation (UI polish, usability, bug fixing, website, Gumroad, marketing, packaging, v5.0 RC).

### v4.12.1 — 2026-08-03 — Professional HTML Report Redesign (presentation-only)
- **HTML report redesigned to commercial-grade / enterprise quality** — executive-dashboard header (verdict hero, KPI cards, conic-gradient severity donut, risk ring gauge — all pure CSS, offline-safe), light/dark/system themes with persisted toggle, sticky TOC sidebar, native `<details>` collapsible evidence, print-to-PDF output. Template full rewrite in `templates/report.html.j2` + CSS-class/markup edits in `core/reporter.py`.
- **No literal `&` in output** (validation escaping contract): inline JS uses nested `if`s; separators are literal UTF-8.
- **Harness consistency**: `tools/report_sample.py` now renders through the production `Reporter.generate_html` path (FAIL/VULNERABLE filtering), so sample data always matches real scans.
- **Performance**: `generate_html` ≈ 43.7 ms/report, ~85 KB HTML. No overflow at 1440/1024/390 px; no console errors; theme persists across reload.
- **Docs**: `project_docs/html_report_redesign.md` (full design-system + before/after documentation).
- Gates: validation 0/0, engine 0/0, `REGRESSION=0` (PASS=10, WARNING=6), `PARITY=0`.

### v4.12.0 — 2026-08-03 — Assessment Consistency & Engine Freeze (SOP v4.0 Phase 4.4)
- **Assessment Engine declared feature-complete & stable** — the pipeline now holds `PARITY=0`, `REGRESSION=0`, validation `0/0`, engine `0/0`. This is the stable release checkpoint for the completed engine architecture.
- **Warning-aware assessment** (`core/assessment_engine.py`): `warning_count` propagated into `AssessmentSummary` and assessment-confidence; a scan with warnings but no confirmed vulnerabilities gets a bounded `warning_uncertainty` penalty (`min(10, warning_count*3)`) and an `INFO` "Warning only" assessment tier.
- **Verdict threshold tuning**: escalation ladder requires materially higher evidence (critical verified at risk≥80, high verified ≥60, high material ≥45, medium ≥35) — the verdict no longer over-states severity on borderline scores; a warning-only scan resolves to `INFO`.
- **Executive assessment improvements** (`core/executive_summary.py`): warning-only prose, key-findings bullets, and positive highlights ("X warnings, no confirmed vulnerabilities, Y checks passed") instead of falling through to the all-clear text; `has_vulns` threaded through all helpers.
- **Scope freeze**: no new engine features unless they fix a verified defect. Roadmap shifts to product quality (GUI/HTML/PDF redesign, UX, website, marketing, release prep).
- Gates: validation 0/0, engine 0/0, `REGRESSION=0` (PASS=10, WARNING=6), `PARITY=0`.

### v4.11.0 — 2026-08-02 — Confidence Normalization (SOP v4.0 Phase 4.3)
- **Calibration implemented under `SEA_CALIBRATION` flag**. When OFF (default), engine is byte-identical to v4.9.0 (`REGRESSION=0`, `PARITY=0`, validation `0/0`, engine `0/0`). When ON, the calibrated profile is used.
- **Added `CALIBRATED_CONFIDENCE`** in `core/assessment_config.py` — normalized caps: CAP_VERIFIED 90→95, CAP_CONFIRMED 85→95, CAP_LIKELY 75→80, CAP_POSSIBLE 60→55; EVIDENCE_QUALITY_WEIGHT=1.0.
- **`confidence_engine._profile()`** selects frozen vs calibrated dict; `compute()` blends `evidence_quality` into base when calibrated (audit C2 — previously unused).
- **Confirmed evidence** verifies as **likely** (up from possible) — the C1 fix; rich evidence (payload+snippet+passes) lifts confidence via the quality blend.
- **Per-scenario deltas** (calibration_benchmark.json): pass_verified 75→90, confirmed_single 70→85 (possible→likely), confirmed_multi 75→90 (possible→likely), likely_warning 60→70, host_reflected 75→88 (possible→likely), sql_verified 80→95.
- **Scan-level**: risk_score 38→65, assessment_confidence 80→90 (coverage and vulnerability count unchanged).
- **Added `tests/calibration_benchmark.py`** → `tests/fixtures/calibration/calibration_benchmark.json`; **`project_docs/calibration_phase3.md`** (architecture + cap reconciliation + per-scenario deltas + rationale).
- **Next**: Phase 4.4/4.5 (verification reconciliation, severity-vs-evidence calibration) — **NOT started**, gated on Phase 4.3 review.

### v4.10.0 — 2026-08-02 — Engine Calibration Foundation (SOP v4.0 Phase 4.2)
- **Behavioral-parity foundation** for Phase 4 confidence normalization. **No consumer-visible change**: confidence, risk, severity, report, and assessment output are byte-identical to v4.9.0 (`PARITY=0`, `REGRESSION=0`, validation `0/0`, engine `0/0`).
- **Added `core/assessment_config.py`** — single source of truth for all engine constants (`EVIDENCE`, `CONFIDENCE`, `VERIFICATION`, `SEVERITY`, `RISK`, `COVERAGE`, `ASSESSMENT`) + helper functions. Every engine now imports from it (identical values, no logic change): `confidence_engine`, `evidence_engine`, `verification_engine`, `severity_engine`, `risk_engine`, `coverage_engine`, `assessment_engine`, `decision_engine.RiskCalculator`, `pipeline` (report map).
- **Added `core/feature_flags.py`** — `SEA_CALIBRATION` gate (default `off`, inert) with `CalibrationCollector` recording per-finding/scan observations to `SEA_CALIBRATION_DIR` (default `reports/calibration`) when set to `report`. Wired into `core/pipeline.py` (`run_engine_pipeline` + `run_assessment_pipeline`); proven inert (regression under `SEA_CALIBRATION=report` still `REGRESSION=0`).
- **Added `tests/calibration_capture.py`** → `tests/fixtures/calibration/parity_baseline.json` (deterministic canonical scenarios through the real pipeline); **`tests/calibration_parity_test.py`** recomputes and asserts `PARITY=0` against the frozen baseline — any future change that drifts a visible number fails here.
- **`decision_engine.RiskCalculator`** now reads the shared `RISK` config (resolves a latent drift vs `RiskEngine`; live paths use `RiskEngine` so no numeric change).
- **Documented**: `project_docs/calibration_foundation.md` (architecture + constants + flags + snapshot + regression report); `project_docs/calibration_audit.md` (P4.1 findings C1–C8).
- **Next**: Phase 4.3 confidence normalization, **only under the `SEA_CALIBRATION` flag**, holding `PARITY` and `REGRESSION` via the new baseline guard.

### v4.9.0 — 2026-08-02 — Scanner Quality Pass (SOP v4.0 Phase 3.10)
- Four detection-accuracy scanners improved with deterministic Before/After benchmarks + validation:
  - **Sensitive Files**: removed benign public files from the exposure catalogue (robots.txt, README, LICENSE, package.json, sitemap.xml, Makefile, .gitignore) + `_raises_wrapper_page` guard (a 200 custom-HTML "Not Found" page is not exposure). `benchmarks/sensitive_files_benchmark.py`: **Before 3 TP/1 FP/1 TN (precision 75%) → After 3 TP/0 FP/0 FN/2 TN (100%/100%)**. §43.
  - **HTTP Methods** (`scanners/http_methods.py`): allowance = **2xx or 401 only**; 3xx/404/403/405/5xx not allowed; dangerous set PUT/DELETE/TRACE/CONNECT/PATCH/PURGE → dynamic `http_methods_confidence` + `detection_methods`. `benchmarks/http_methods_benchmark.py`: **4 TP/1 FP (redirect)/1 TN → 4/0/0/2 (100%/100%)**. §44.
  - **Headers Security** (`scanners/headers.py`): single-source exact-once fingerprint (`header_present`/`header_missing`/`header_issues`/`header_confidence`) + `MISSING_SEVERITY` weights; eliminated duplicate weak-CSP reporting. `benchmarks/headers_benchmark.py`. §45.
  - **Source Code Leaks** (`scanners/source_leaks.py`): ambient categories (Emails, Comments, Debug Information, Source Maps) fire only alongside a real confirmed leak; confirmed categories dedupe to one each; added AWS/Azure/AMAZON/_KEY + `AKIA` patterns. `benchmarks/source_leaks_benchmark.py`: **Before 0 TP/4 FN on fixtures → After 4 TP/0 FP/0 FN/2 TN (100%/100%)**. §46.
- **Formally documented unchanged** (audited): Technology Detection, DNS, TLS/SSL, Open Ports, Host Header Injection — full rationale in `project_docs/scanner_quality_report.md` (network-bound or already-compliant; no local FP/FN model to improve).
- **Gates**: validation 0 errors / 0 real failures; engine_tests 0/0; regression `REGRESSION=0` (PASS=10, WARNING=6).
- **Phase 4 is gated** on review of the scanner quality report.

### v4.8.0 — 2026-08-02 — Cookies Security Detection Accuracy (SOP v4.0 Phase 3.9)
- **`scanners/cookies.py`** rewritten from an informational attribute listing into issue-driven, evidence-only detection with session discrimination:
  - **Session vs asset discrimination** (`_is_session_like`): only **session-recognizing** cookies are scored — those whose name matches a `SESSION_FRAGMENTS` token (`sid`/`session`/`auth`/`token`/`jwt`/`asp`/`laravel`/…) or any `__Host-`/`__Secure-` prefixed cookie. Non-session preference/analytics cookies are deliberately **not** flagged.
  - **Issues emitted** via structured evidence (`matched_signal`/`type`/`severity`/`reliability=high`/`reproducible`): `missing_secure` (session=high, prefixed=**critical**), `missing_httponly`, `missing_samesite`, `samesite_none`, `prefix_misuse` (a `__Host-` cookie with a `Domain` is illegal), `persistent_session` (>7-day expiry), `broad_domain` (single-label TLD scope), `missing_path`.
  - **Raw `Set-Cookie` supplement** (`_raw_cookies` → `resp.raw.headers.getlist`): the requests cookiejar **silently drops** cookies whose scope it rejects (`Domain=com`), so those `broad_domain` violations are recovered from the raw header — closes the v3 false-negative where they were invisible.
  - **Dynamic confidence** `_confidence`: reproducible 0–100 from issue count/severity → `cookie_confidence` (0 when fully hardened).
  - **`benchmarks/cookies_benchmark.py`** — local deterministic fixture (5 vulnerable + 3 clean) → `reports/cookies_benchmark.json`.
- **Benchmark Before/After**: **Before = 0% (all 5 FNs; scanner set attribute evidence but never `cookie_issues`)**, **After = 100% (5/5), 0 FP, 0 FN, 3 TN**; `/unsecure_session` (`missing_secure`), `/no_httponly_session` (`missing_httponly`), `/prefix_misuse` (`missing_samesite`+`missing_secure`), `/persistent_session` (`persistent_session`), `/broad_domain` (`broad_domain` via raw header) detected; `/good_session`, `/asset_nosession`, `/clean_batch` correctly **not** flagged.
- **FP reduction**: non-session asset cookie (`visitor=…; Path=/`) not flagged; fully hardened cookie (`Secure; HttpOnly; SameSite=Strict; Path=/`) yields zero issues + `cookie_confidence=0`.
- **Evidence**: fingerprint `cookie_issues` (type/name/severity/recommendation) + `cookie_confidence` + `cookies` (per-cookie `secure`/`httponly`/`samesite`/`prefix`/`domain`/`path`/`expires`/`session_like`).
- **Validation**: `test_validation.py` 0 errors/0 warnings (new §42 covers missing Secure, missing HttpOnly, `__Host-` prefix misuse critical, far-future persistence, broad-domain raw recovery, `__Host-`+`Domain` prefix misuse, `SameSite=None`, hardened clean (no FP), asset cookie not flagged, dynamic confidence scaling); engine_tests 0/0; regression `REGRESSION=0` (PASS=10, WARNING=6, unchanged).

### v4.7.0 — 2026-08-02 — CORS Configuration Detection Accuracy (SOP v4.0 Phase 3.8)
- **`scanners/cors.py`** rewritten (evidence-only):
  - **Cross-method confirmation** (`PROBE_METHODS` GET+POST): every origin is probed in hunting both GET and POST; a policy that reflects an origin on only one method is never missed — fixed the real v3 **false negative** (`/post_only`).
  - **Credentials-aware** downgrade for FP reduction: wildcard/reflection **with** `Allow-Credentials: true` → `confirmed`; **without** → `likely` (a public credential-less asset is no longer an authenticated-read report).
  - **Multiple-origin** aggregation (`multiple_origin`) when both `evil.com` and `attacker.com` are allowed.
  - **Preflight (OPTIONS)** `_probe_preflight`: OPTIONS with malicious origin + requested method; reflects origin/ev attempts, captures echoed methods.
  - **Dynamic confidence** `_confidence`: reproducible 0–100 (independent origins, credentials, multiple origins, cross-method reproduction, `Vary: Origin`) → `cors_confidence`.
  - **`benchmarks/cors_benchmark.py`** — local deterministic fixture → `reports/cors_benchmark.json`.
- **Benchmark Before/After**: **Before = 80% (1 FN `/post_only`)**, **After = 100% (5/5), 0 FP, 0 FN, 2 TN**; `/reflected`, `/reflected_creds`, `/wildcard_creds`, `/null`, `/post_only` detected; `/allowlist`, `/no_acao` correctly **not** flagged.
- **FP analysis**: credential-less wildcard/reflection → `likely` (not confirmed evidence for an authenticated read); allowlist/no-AC namespace never signal.
- **Evidence**: per-signal `acao`/`acac`/`vary`/`methods`/`vary_missing_origin`/`reliability`/`reproducible`; fingerprint `cors_confidence`/`cors_cross_method`/`cors_multiple_origin`/`cors_credentials`/`cors_vary`.
- **Validation**: `test_validation.py` 0 errors/0 warnings (new §41 CORS covers wildcard+creds, reflection, null, credential-less downgrade, cross-method POST detection, multiple-origin aggregation, preflight confirm, restrictive clean, dynamic confidence scaling, structured metadata); engine_tests 0/0; regression `REGRESSION=0` (PASS=10, WARNING=6, unchanged).

### v4.6.0 — 2026-08-02 — CSRF Protection Detection Accuracy (SOP v4.0 Phase 3.7)
- **`scanners/csrf.py`** upgraded with token/enforcement/randomness, SameSite, Origin/Referer and framework detection:
  - **Token detection**: broadened name recognizers + framework conventions (Django/Laravel/Rails/ASP.NET/Flask-WTF/Spring/Yii/Craft) via field-name and meta markers (`_detect_framework`).
  - **Enforcement** (`_token_enforced`): a token is enforced only when the server rejects BOTH a no-token and a wrong-token submission while the baseline POST processes normally; a static-success page or a broken action can no longer cause an FP/FN.
  - **Randomness** (`_token_weak`): flags tokens shorter than 16 chars or with low Shannon entropy as `weak_token`; a per-page fresh token is a positive `token_rotates`.
  - **SameSite** (`_samesite_profile`): a SameSite=Lax|Strict session cookie MITIGATES a missing token (FP guard); SameSite=None does not.
  - **Origin/Referer** (`_cross_origin_accepted`): per-form cross-origin probe; accepted → `cross_origin_accepted` issue, rejected → `origin_validated` positive.
  - **`benchmarks/csrf_benchmark.py`** — local deterministic fixture (`/no_token`, `/token_ignored`, `/weak` vs `/static`, `/samesite`, `/clean`) → `reports/csrf_benchmark.json`.
- **Benchmark result**: **detection rate 100% (3/3), 0 FP, 0 FN, 3 TN**; `/no_token` (`no_token`+`cross_origin_accepted`), `/token_ignored` (`token_not_enforced`+`cross_origin_accepted`), `/weak` (`weak_token`) detected; `/static` (enforced+protected), `/samesite` (SameSite mitigation) and `/clean` correctly **not** flagged.
- **FP analysis**: a SameSite=Lax/Strict session turns missing-token into a positive (never flagged); only short/low-entropy tokens are `weak_token` (per-page reuse is normal, not an issue); cross-origin requires an identical-to-baseline response.
- **Evidence**: per-observation structured `raw_data` (`technique`, `form_method`, `same_site`, `framework`, `reliability`, `reproducible`, `samesite_mitigated`); issues are `request_response`.
- **Validation**: `test_validation.py` 0 errors/0 warnings (new §31 covers Django framework + token-enforced positive + no-issues, no-token flag, unenforced-token flag, weak-token flag, cross-origin flag, SameSite Lax FP guard, SameSite cookie parsing, clean-page, structured issue metadata); engine_tests 0/0; regression `REGRESSION=0` (PASS=10, WARNING=6, unchanged).

### v4.5.0 — 2026-08-02 — Open Redirect Detection Accuracy (SOP v4.0 Phase 3.6)
- **`scanners/open_redirect.py`** upgraded with host-derived off-site classification, evidence-only scanning, and richer evidence:
  - **Host-derived off-site classification** (`_is_off_site`): a redirect is only an open redirect when its **effective target host** differs from the request's own host. Same-host redirects (even containing a suspicious domain) and same-origin relative `Location` paths are **never** classified as open redirects — closing the largest substring-scanner FP class.
  - **Ambiguous-vector fallback**: tokens that defeat a strict URL parser (`%2F`, `%252F`, `//host`, credential/authority confusion) fall back to an explicit off-host substring check so detection is preserved.
  - **Evidence & techniques**: each confirmed observation carries `detected`, `target_host`, `off_site` and `detection_method` in `raw_data` + fingerprint; techniques `absolute`, `relative`, `protocol_relative`, `encoded`, `double_encoding`, `redirect_chain`; `fingerprint['redirect_targets']` aggregates hosts.
  - **`benchmarks/open_redirect_benchmark.py`** — deterministic local fixture (`/external`, `/coded` → 302 off-site; `/internal` same-host, `/same_origin` relative → negative) → `reports/open_redirect_benchmark.json`.
- **Benchmark result**: **detection rate 100% (2/2), 0 FP, 0 FN, 2 TN**; `/external` and `/coded` detected; `/internal` (same-host) and `/same_origin` (relative) correctly **not** flagged — both were FPs under the v3 substring matcher.
- **Validation**: `test_validation.py` 0 errors/0 warnings (new §30 covers external detection + host recording + ≥2-technique cross-validation, encoded detection, same-host FP control, same-origin relative FP control, POST detection, clean page, `target_host`/`off_site` metadata, clean no-param path); engine_tests 0/0; regression `REGRESSION=0` (PASS=10, WARNING=6, unchanged).

### v4.4.0 — 2026-08-02 — SSTI Detection Accuracy (SOP v4.0 Phase 3.5)
- **`scanners/ssti.py`** upgraded with per-parameter baseline FP-guard, enhanced engine fingerprinting, and context-variant probe correlation:
  - **Baseline FP-guard**: for each `(param, method)` the scanner requires BOTH arithmetic products (`49` and `72`) to be ABSENT from the benign per-parameter response (`_evaluation_credible`, cached). A page that statically prints the numbers can never be flagged.
  - **Enhanced fingerprinting** (`ENGINE_FINGERPRINTS` + `_match_engines`): distinctive real markers per engine (Jinja2/`jinja2.exceptions`, FreeMarker/`FreeMarker template error`, Twig/`Twig\Error\SyntaxError`, Velocity/`org.apache.velocity`, Smarty/`SmartyBC`, ERB/`ActionView::Template`); case-insensitive matching.
  - **Context-variant probes** (`ENGINE_PROBES` + `_render_text`): every confirmed evaluation probes the parameter with a second, novel render construction and scans for fingerprints, corroborating engine identification.
  - **Evidence correlation**: observations + `engine_evidence` carry `fingerprint_consistent` and `markers_matched`; cross-validation enumerates confirmed engines; `fingerprint['engine_evidence']` aggregates.
  - **`benchmarks/ssti_benchmark.py`** — local deterministic fixture (generic evaluator + FreeMarker fingerprint + 3 controls) → `reports/ssti_benchmark.json`.
- **Benchmark result**: **detection rate 100% (2/2), 0 FP, 0 FN, 3 TN**; `/math` confirmed 5 engines, `/fm` reported freemarker with `fingerprint_consistent`, `/fp_echo` (reflection-only) + `/fp_baseline` (static numbers) correctly **not** flagged.
- **Validation**: `test_validation.py` 0 errors/0 warnings (new §29 covers generic ≥2 engines, FreeMarker engine + marker correlation, POST-field, reflection echo negative, static-numbers baseline negative, clean, `fingerprint_consistent` flag, clean no-param path); engine_tests 0/0; regression `REGRESSION=0` (PASS=10, WARNING=6).
- **FP analysis**: baseline guard closes the "page statically contains 49/72" class (primary + confirm); reflection-only echo has no evaluated magic numbers; fingerprint markers are distinctive engine strings (never generic words). Documented in `project_docs/CHANGELOG.md` §4.4.0.

### v4.3.0 — 2026-08-02 — LFI Detection Accuracy (SOP v4.0 Phase 3.4)
- **`scanners/lfi.py`** upgraded with a per-parameter baseline FP-guard, hardened markers, and richer payload diversity:
  - **Baseline FP-guard**: before a known-file marker is accepted, the scanner fetches the *benign* response for that parameter (neutral token for GET, original field value for POST; cached once per `(param, method)`) and only reports the marker if it is **absent** from that baseline (`_signature_hit`). Unconditional `root:x`/`localhost`/OS-banner pages can no longer be flagged.
  - **`baseline_excluded=True`** recorded on every emitted observation's `raw_data` — an auditable accuracy claim on each finding.
  - **Wider markers**: `/etc/shadow` (`root:*:`, `daemon:*:`), extra passwd anchors (`/root:/bin/bash`), `/etc/hosts` (`localhost.localdomain`), `/proc/self/environ` (`DOCUMENT_ROOT=`), Apache config (`ServerToken`), Windows `boot.ini` (`[boot loader]`, `system32\ntoskrnl.exe`) and `system.ini` (`[drivers32]`).
  - **Payload diversity**: new traversal targets (`etc/shadow`, `etc/apache2/apache2.conf`, `windows\system.ini`, `boot.ini`), more confirm paths, and broader encoding variants (`triple_url`, `mixed_slash`, `overlong_utf8`, `double_encoded_backslash`) so WAF-filtered plain traversal is still caught.
  - **Marker hygiene**: removed common English words (`localhost`, `Debian`, `Ubuntu`) as standalone proof — only distinctive OS-format anchors remain, and every match is baseline-gated.
- **`benchmarks/lfi_benchmark.py`** — deterministic local fixture (POSIX / Windows / shadow / WAF-encoded endpoints + `/baseline` unconditional-marker control + `/clean`) → `reports/lfi_benchmark.json`.
- **Benchmark result**: **detection rate 100% (4/4), 0 FP, 0 FN, 2 TN**; `/baseline` (the Phase 3.4 FP class — page always renders `root:x:`) and `/clean` correctly **not** flagged.
- **Validation**: `test_validation.py` 0 errors/0 warnings (new §28 covers POSIX traversal + disclosure, Windows config files, encoding bypass under a filtering WAF, unconditional-marker baseline negative control, clean-page, `baseline_excluded` on every observation, clean no-param path); engine_tests 0/0; regression `REGRESSION=0` (PASS=10, WARNING=6).
- **FP analysis**: baseline guard kills the "page always renders marker" class; marker hygiene removes bare `localhost`/`Debian`/`Ubuntu`; encoding bypass requires ≥2 independent constructions. Documented in `project_docs/CHANGELOG.md` §4.3.0.

### v4.2.0 — 2026-08-02 — SSRF Detection Accuracy (SOP v4.0 Phase 3.3)
- **`scanners/ssrf.py`** upgraded with provider-aware cloud metadata, redirect-chain analysis, stronger correlation + FP reduction:
  - **Cloud metadata per provider** (`CLOUD_PROVIDERS`): AWS EC2 IMDS, Azure Instance Metadata, GCP Metadata Server, DigitalOcean, OpenStack/cloud-init, Alibaba Cloud ECS, Oracle Cloud — each with endpoints + marker vocabulary. Exact match guard (`_metadata_body_hit`): markers must not be a substring of the requested URL, so an app that echoes the URL string can never satisfy a metadata finding. GCP/Azure request headers (Metadata-Flavor / Metadata) are propagated.
  - **Provider classification + aggregation**: each observation carries `provider`; `_aggregate_providers` folds providers across techniques into `fingerprint['cloud_provider']` (no single-signal provider claim).
  - **Redirect-chain analysis** (`_walk_server_chain`): walks the *server-side* chain (each hop re-sent through the parameter, bounded to REDIRECT_MAX_HOPS); an internal/cloud-metadata `Location` hop yields a `redirect_chain` observation with the full hop list in evidence.
  - **Redirect-safe probing**: SSRF probes no longer auto-follow redirects, so an open-proxy `Location` to an internal host never drags the client off-target or into latency.
  - **FP reduction**: `internal_access` requires a distinct **200** differing from baseline by `>300` bytes and excludes generic error bodies (404/403/500/503 …) — a normal app error page can no longer be read as internal reachability. Metadata echo guard + ≥2 independent paths per provider.
  - **Evidence correlation**: `detection_method`, `provider`, `redirect_chain`, `confirm_payload` in `raw_data`; cross-validation names the cloud provider(s).
- **`benchmarks/ssrf_benchmark.py`** — deterministic local fixture (6 endpoints: cloud metadata/internal fetch/URL-fetch error/server-side redirect + URL echo + generic 404) → `reports/ssrf_benchmark.json`.
- **Benchmark result**: **detection rate 100% (4/4), 0 FP, 0 FN, 2 TN**; `/meta` reported **AWS + Azure + GCP** classification; `/redir` → redirect-chain; `/echo` + `/clean404` not flagged.
- **Validation**: `test_validation.py` 0 errors/0 warnings (new §27 covers AWS/Azure/GCP classification, GCP header detection, metadata does-not-fire on echo, generic 404 not internal, redirect-chain + hops, multi-technique cross-validation + provider aggregation, clean no-param path); engine_tests 0/0; regression `REGRESSION=0` (PASS=10, WARNING=6).
- **FP analysis**: echo guard (marker-not-in-URL), internal restricted to distinct 200 minus generic body, redirect only on genuine `Location→internal`. Documented in `project_docs/CHANGELOG.md` §4.2.0.
- **External labs** (Juice Shop / DVWA / bWAPP / metadata-fetch lab) via `python -m benchmarks.ssrf_benchmark --targets <url>...`.

### v4.1.0 — 2026-08-02 — XSS Detection Upgrade (SOP v4.0 Phase 3.2)
- **`scanners/xss.py`** upgraded with context-aware detection + sink classification + stored/DOM support signals + escape FP guard:
  - **Context-aware payloads** (`context_payloads`): per-context production payload sets — HTML (script tag / img onerror / svg onload / body onload), attribute (double/single-quote breakout, autofocus, unquoted on/off), JavaScript (`</script>`, `;alert(1)`, `"/alert(1)//`, `template-literal `${alert(1)}``). Ordered worst-first.
  - **Sink classification** (`sink_rules` + `_classify_sink`): every confirmed observation reports exactly where the payload executed — `script_tag`, `img_event`, `svg_event`, `body_event`, `quote_breakout`, `unquoted_event`, `script_breakout`, `js_string_breakout`, `template_breakout` — carried into evidence `raw_data`.
  - **Stored-XSS probe** (`_check_stored`): after a confirmed reflected context, one POST persists the payload, one payload-free GET proves survival → independent `stored_persistence` support evidence.
  - **DOM-source indicative** (`_check_dom`): a reflected value that also reaches a dangerous sink (`.innerHTML=`/`.outerHTML=`/`document.write(`/`.insertAdjacentHTML`/`eval(`/`.setAttribute`/`.textContent=`/`.href=`/`.location=`) inside the same inline `<script>` → `dom_source` support signal. **No rendering engine** — explicitly indicative only, never standalone.
  - **Escape guard** (`_strip_escaped`): entity-escaped tags (`&lt;...&gt;`, `&quot;...&quot;`) are stripped before marker/context matching, so an escaped (inert) page can no longer trigger a finding despite literal `src=`/`onerror=`/`alert(1)` surviving encoding.
- **`benchmarks/xss_benchmark.py`** — deterministic local fixture (3 vulnerable + 2 clean: HTML reflection, attribute reflection, DOM sink, static page, escaped page) → `reports/xss_benchmark.json`.
- **Benchmark result**: local fixture **detection rate 100% (3/3), 0 FP, 0 FN, 2 TN**; `/html`+`/attr` confirmed with sink classification, `/dom` added `dom_source`, `/escaped` correctly **not** flagged (the Phase 3.2 FP class).
- **Validation**: `test_validation.py` 0 errors/0 warnings (new §26 covers script-tag html context + sink, attribute breakout, DOM indicative, DOM stored probe, context-payload sets, engine dynamic confidence, clean no-param path); engine_tests 0/0; regression `REGRESSION=0` (PASS=10, WARNING=6).
- **FP analysis**: escaped pages closed by `_strip_escaped`; DOM is indicative-only (no renderer); stored only after confirmed execution context — all bound false positives.
- **External labs** (Juice Shop / DVWA / bWAPP / PortSwigger Web Academy XSS labs) run via `python -m benchmarks.xss_benchmark --targets <url>...` when reachable.

### v4.0.0 — 2026-08-02 — SQL Injection Upgrade (SOP v4.0 Phase 3.1)
- **`scanners/sqli.py`** upgraded with two new injection techniques + DBMS fingerprinting + structured evidence:
  - **UNION-based** (`union_based`): `ORDER BY` column-count oracle → `UNION SELECT` reflects a unique marker → a second reordered marker confirms. Non-regex corroboration.
  - **Stacked queries** (`stacked_queries`): gated on a prior MSSQL/PostgreSQL/MySQL fingerprint; stacked conditional delay confirmed across two payloads (< never a sole signal).
  - **DBMS fingerprinting** (`_db_fingerprint()`): provenance-aware per-DB confidence (`database_fingerprint`); `fingerprint['database']` backward-compatible.
  - **Structured evidence**: `detection_method`, `independence`, `reproducibility`, `confirm_payload`, `database`, `database_confidence` + per-technique timing/comparison dicts in `raw_data`.
  - **Confidence** remains fully engine-computed (evidence count, independent observations, verification passes, cross-validation) — never static.
- **`benchmarks/sqli_benchmark.py`** — deterministic local fixture measuring TP/FP/FN/TN/detection-rate/avg-scan-time + external-target hook → `reports/sqli_benchmark.json`.
- **Benchmark result**: local fixture **detection rate 100% (4/4), 0 FP, 0 FN, 2 TN** (`union_based`/`stacked_queries`/`error_based`/`time_based`/`boolean_based`); before (legacy v3) ≈75% (UNION/stacked were FNs).
- **Validation**: `test_validation.py` 0 errors/0 warnings (new §25 covers UNION oracle+reflection, non-regex corroboration, error fingerprint, boolean dual-pair, stacked gating, DB-fingerprint provenance, structured evidence, dynamic confidence, clean no-param path); engine_tests 0/0; regression `REGRESSION=0` (PASS=10, WARNING=6).
- **FP analysis**: UNION requires two reflected markers; stacked gated on DB fingerprint; boolean requires two independent pairs; known limits documented (WAF timeout → time-based FN, generic-500 → UNION timeout, pathological page reflection).
- **External labs** (Juice Shop / DVWA / Mutillidae / WebGoat / bWAPP / PortSwigger Academy) run via `python -m benchmarks.sqli_benchmark --targets <url>...` when reachable.

### v3.10.0 — 2026-08-02 — Advanced Smart Crawling (SOP v4.0 Phase 2)
- **New dedicated crawling subsystem** replacing the legacy single-module crawler, behind a fully backward-compatible public API (`from core.crawler import Crawler` still works — same `crawl()`/`extract_post_forms()` surface, same `visited`/`pages`/`diag`, 49 skip extensions):
  - `core/crawler/crawler.py` — bounded breadth-first orchestrator with an explicit queue (no recursion).
  - `queue.py` — `CrawlQueue`: BFS + per-URL `depth`, enqueued-set de-dup, max-depth limits (infinite-precrawl safety).
  - `url_normalizer.py` — `URLNormalizer`: fragments, duplicate slashes, dot-segments, default ports, lower-cased hosts and common tracking parameters (utm_*/fbclid/gclid/ref/…) → one canonical URL per resource.
  - `scope_manager.py` — `ScopeManager`: `domain | subdomain | path | all`, plus `include_subdomains` and include/exclude regex patterns; keeps the crawler on-target.
  - `robots_parser.py` — downloads/parses robots.txt (allowed, disallowed, crawl-delay, sitemaps). Disallowed paths are only honoured when `respect_robots=True` (default off — must never silently prune).
  - `sitemap_parser.py` — sitemap.xml / sitemap-index / gzip parsing, merged into the queue and de-duplicated.
  - `link_discovery.py` — anchors, navigation, form actions, canonical, meta-refresh targets + static JS URL extraction (no rendering).
  - `page_classifier.py` — automatic classification (Login/Admin/API/Dashboard/User Profile/Search/Product/Documentation/Static/Error/Home) that feeds the attack-surface report.
  - `deduplicator.py` — URL + redirect + content-hash de-duplication (three layers).
  - `crawl_statistics.py` — counter set exposing both legacy `diag` keys and Phase 2 keys (duplicates/redirects/failed/duration/sitemap/robots/classifications).
- **Budgeted limits**: `max_pages`, `max_depth`, `max_requests`, `max_duration` with graceful abort when reached.
- **`Scanner` config** (`core/config.py`): new `max_depth`, `max_crawl_requests`, `max_crawl_duration`, `crawl_strategy`, `crawl_scope`, `include_subdomains`, `crawl_include/exclude_patterns`, `respect_robots`, `parse_sitemap`. Anonymous defaults unchanged.
- **`main.py` + GUI `ScanWorker`** now build the crawler with the new options and pipe Phase 2 metrics into `ScanResult` (`crawl_duplicates/redirects/failed/duration/sitemap/robots`, `attack_surface`, `crawl_classifications`).
- **GUI** (`gui/pages/scanner_page.py`): new "Crawl Settings" card — Max Depth, Max Duration, Scope, Include subdomains, Respect robots.txt, Parse sitemap.xml → `build_crawl_config()` → `start_scan(crawl=...)`.
- **Reporting** (`core/reporter.py`): Attack Surface Summary gains a "Crawl Discovery (Phase 2)" grid — URLs discovered, Login/Admin/API pages, Forms found, JS files, Sitemap entries, Robots entries, Duplicates (both HTML template paths).
- **CLI** (`sea.py`): `--max-pages`, `--max-depth`, `--scope {domain,subdomain,path,all}`, `--include-subdomains`, `--respect-robots`, `--parse-sitemap`, `--no-sitemap`.
- **Validation**: `test_validation.py` 0 errors / 0 warnings (new §24 "Advanced Smart Crawling" covers URL normalization, scope, robots, sitemap, queue/dedup/infinite-precrawl, crawler dedup identity, classification, stats diag, form extraction, CLI flags); engine_tests 0/0; regression `REGRESSION=0` (PASS=10, WARNING=6). End-to-end local-server crawl verified BFS discovery, sitemap merging, robots parsing, dedup, classification + attack surface.
- **Scope guard**: no browser automation, no JS rendering, no login automation, no new vulnerability scanners were added.

### v3.9.0 — 2026-08-02 — Optional Authentication Support (SOP v4.0 Phase 1)
- **Authentication is now optional (anonymous is still the default and unchanged)**. Phase 1 delivers four opt-in authentication methods without touching the anonymous workflow:
  - **New `core/auth/` provider package (standalone — scanners contain no auth logic)**: `AuthSpec` (single input contract) + `BaseProvider`; `cookie_provider.py` (Netscape ≥7 + `name=value` files), `bearer_provider.py`, `jwt_provider.py`, `header_provider.py` (repeatable `"Name: Value"`), `session_validator.py` (`SessionValidationResult` + `SessionValidator` — probes a **fresh** `requests.Session()` so the tracked crawl session is never polluted), `authentication_manager.py` (`AuthenticationManager` facade: `build`/`apply_to`/`validate`/`activate`/`mark_invalid`), `__init__.py` re-exports the `core.auth_manager` API as a facade.
  - **`AuthenticationManager.build(None)` → anonymous no-op; unsupported/empty credentials raise `ValueError`; `mark_invalid()` flags token methods as `token_invalid` and cookies as `session_expired`** so a failed session never claims to be authenticated.
  - **CLI** (`sea.py`): `sea scan <target>` anonymous by default; `--cookies FILE` / `--bearer FILE` / `--jwt FILE` / `--header "Name: Value"` (exactly one, exit 2 on conflict); `--no-validate-session`, `--mode quick|standard|deep`, `--threads/--timeout`, `--no-auth-detection`, report-format flags, `--report-dir`. UTF-8 stdio wrapper fixes Rich banner crashes when stdout is piped on Windows cp1252.
  - **`main.py`**: non-interactive `run_scan(target, *, auth_spec=None, report_formats, report_dir)` — login detection stays informational/non-blocking (`_show_login_detected_hint`); session validation runs only when auth is enabled; on failure the scan continues anonymously with a clear warning.
  - **`core/auth_manager.py`**: `AUTH_METHOD_LABELS['public']` now "Anonymous" (was "Public Scan"); added `'jwt': 'JWT Token'`, `'headers': 'Custom Headers'`; `AuthSession.set_jwt_token()` / `configure_headers()`. `core/finding.py` `evaluate_auth_state()` treats `jwt`/`headers` like bearer for token-invalid detection.
  - **GUI** (`gui/pages/scanner_page.py`): new "Authentication (Optional)" card — enable checkbox reveals/hides the type radios + per-type fields (cookies file/string, bearer/JWT file/value, headers editor) + "Validate session" checkbox; `build_auth_spec()` → `ScanController.start_scan(auth_spec=...)` → `ScanWorker` (build/attach/validate/log, re-crawl to count protected pages, login-detection informational log). `gui/widgets/summary.py` shows "Auth: <mode> (session valid/invalid)".
  - **Reporting**: `stats['auth']` extended with `authenticated`/`mode`/`session_valid`/`session_checked`; HTML Authentication section now shows Mode, Authenticated, Session Valid, Protected Pages Scanned (all secrets redacted); anonymous scans render no auth section (default UX unchanged).
- **Docs**: `PROJECT_STATE.md`, `project_docs/CHANGELOG.md` (3.9.0), `SOP.md` (auth usage + `core/auth` ownership), `docs/ENGINE_ARCHITECTURE_V3.md`.
- **Validation**: `test_validation.py` 0 errors / 0 warnings (new §23 covers `core.auth` providers, `AuthSpec`, `AuthenticationManager`, `SessionValidator` via patched `requests.Session`, and `sea` CLI parsing); engine_tests 0/0; regression `REGRESSION=0` (PASS=10, WARNING=6). End-to-end `sea` scans against a local server verified all three modes: **valid bearer** (session validated, `authenticated=true`, `session_valid=true`), **invalid bearer** (validation fails → continues anonymously, `state=token_invalid`, `session_valid=false`), **anonymous** (no auth section). GUI `ScanWorker` flow verified offscreen (valid/invalid/anonymous + login-detection hint).

### v3.8.0 — 2026-08-02 — Assessment Orchestrator Integration (A9)
- **Single assessment lifecycle per scan (A9 landed)**. Every production orchestrator now calls `scan_result.assess()` exactly once and reads the one immutable `Assessment`:
  - `core/pipeline.py`: `run_assessment_pipeline` is **idempotent** — full lifecycle (correlation boosts → Risk → Coverage → Assessment → Executive Summary) built once and stored on `scan_result.assessment`; re-calls return the existing object (correlation never applied twice).
  - `core/finding.py`: `ScanResult.assessment` attribute + `assess(**kwargs)` gateway. Legacy `get_statistics`/`get_coverage`/`get_execution_states`/`get_overall_severity`/`calculate_dynamic_risk_score`/`calculate_risk_breakdown`/`run_correlation` **delegate to the stored Assessment** (inline fallback only for un-assessed results used by the test harness); `run_correlation()` returns `[]` once assessed.
  - **CLI** (`main.py`): `run()` calls `self.scan_result.assess()` before summary/reports; `run_scan_on_all_pages()` no longer calls `run_correlation()`.
  - **GUI** (`gui/services/scan_worker.py`): `assess()` replaces `run_correlation()`; `_build_summary` reads `assessment.assessment_confidence`; `gui/main_window.py` + `gui/pages/history_page.py` persist/prefer the Assessment-derived `overall_tier`.
  - **Backend** (`backend/app/scan_runner.py`): OAIST confirmation is now an **engine hook** — `EvidenceBuilder().exploited(...)` evidence, pipeline derives verification/confidence/severity (no direct overrides); final phase reads `assessment.statistics` instead of manual `CorrelationEngine.correlate()` + `get_statistics()`.
  - **Reporters** (`core/reporter.py`, `core/pdf_reporter.py`): `_stats(scan_result)` reads the stored Assessment first (Assessment-first, legacy fallback only for un-assessed).
- **Docs**: `docs/ENGINE_ARCHITECTURE_V3.md` (§7 single lifecycle data flow, §8 backward-compat, Phase A9 table → completed), `docs/TECHNICAL_DEBT.md` (OAIST §3.4 resolved, §4 table, §5 A9 → completed), `project_docs/CHANGELOG.md`, `PROJECT_STATE.md`.
- **Validation**: engine_tests 0 errors/0 warnings; regression `REGRESSION=0` (PASS=10, WARNING=6 — explained band shifts); test_validation 0/0; py_compile clean on all 9 modified files; delegation parity verified (get_statistics == assessment.statistics exact dict, idempotent re-run) on clean_site/sqli_detected/mixed_corpus/scan_incomplete/scan_error. Remaining: live `tests.live_scan_runner` replay (needs a live target or raw `--session` fixture).

### v3.7.0 — 2026-08-01 — Engine v3 Migration Cleanup & Architecture Freeze (A8.9)
- **Archived the v2 decision logic** in `tests/v2_reference.py` (test-only; production never imports it) so nothing is permanently lost: `v2_decide`, `V2DecisionEngine`, `v2_apply_evidence_assessment`, `v2_compute_execution_state` + the archived helpers. The regression harness now compares the archived v2 against the v3 pipeline.
- **Single execution path (freeze)**: `BaseScanner.run()` always calls `run_engine_pipeline()`. Removed `use_engine_pipeline`, the legacy `decide()` branch, `create_safe_finding`/`create_vulnerable_finding`, `verify_multi_pass`, `add_verification_evidence`, `add_payload_evidence`, `capture_response_analysis` from `scanners/base.py`, and `use_engine_pipeline = True` from all 19 scanners.
- **`core/decision_engine.py`** reduced to the standards metadata provider (`STANDARDS/RECOMMENDATIONS/CVSS_DESCRIPTIONS/SEVERITY_BY_MODULE`) + `RiskCalculator` (kept until A9/A10 for `get_statistics()`); `decide()` and all `_*` helpers removed.
- **`core/finding.py`** evidence-only `add_evidence()`; removed `_update_confidence_from_evidence`, `_update_verification_status`, `_highest_evidence_level`, `_build_confidence_explanation`, `compute_execution_state`, `collect_matched_rules`, `EVIDENCE_LEVEL_LABELS`. `verification_label`/`execution_label` are read-only properties (execution falls back to `CoverageEngine.classify_execution_state`).
- **`respect_existing` removed** from `core/pipeline.py` + `core/severity_engine.py` — the module map is the single authority for severity.
- **Harness rewrite**: `tests/engine_paths.py` (`run_v2`/`run_v3` via archived v2 + `run_assessment_pipeline`), `tests/engine_tests.py` (single-writer severity assertions, section 7 AST guard over all scanners, ConfidenceEngine↔v2 parity), `test_validation.py` legacy call sites routed through `tests.v2_reference` / the pipeline.
- **Validation**: `test_validation.py` 0 errors / 0 warnings; engine unit tests green; golden regression `REGRESSION=0` (PASS=10, WARNING=6 — all explained band shifts).
- **Docs**: `docs/TECHNICAL_DEBT.md` rewritten for the A8.9 cleanup (all Batch-6 removal items checked; remaining debt = A9 orchestrator wiring / A10 consumers); `project_docs/CHANGELOG.md`, `SOP.md` (evidence-only scanner authoring), `ENGINE_ARCHITECTURE_V3.md`, `development_progress.txt` updated.

### v3.6.0 — 2026-08-01 — Engine v3 Migration Final Batch (LFI / SSRF / Open Redirect / SSTI) — **19/19 complete**
- **Migrated (19/19 now evidence-only, 0 on `decide()`)**: LFI Detection, SSRF Detection, Open Redirect, and SSTI Detection joined the v3 engine pipeline — the migration is complete. Each `scan()` emits only raw evidence + test counters + fingerprints/metadata; status/severity/confidence/verification/execution-state are derived exclusively by `run_engine_pipeline` (`respect_existing=False`).
- **Improved detection accuracy** (the final batch's focus — repeated confirmation, no single-observation findings):
  - **LFI Detection** — multi-technique `lfi_signals[]` + `files_disclosed` fingerprint: `traversal` (known-file signature reproduces on two distinct paths), `disclosure` (≥2 sensitive-file markers), `os_fingerprint`, `null_byte` (`%00` discloses a file the plain path does not), `encoding_bypass` (URL / double-URL / backslash / dot-overslash, reconfirmed with a second variant), `error_signature`. Adaptive depth 3–8. **2+ techniques** add `cross_validation` (verified) evidence.
  - **SSRF Detection** — multi-technique `ssrf_signals[]` fingerprint: `metadata` (169.254.169.254 / Google computeMetadata markers, reproduced on a second endpoint), `internal_access` (baseline-differential on a private address, reproduced), `error_signature` (`Connection refused` etc., reproduced), `redirect`, `oast` (OAIST out-of-band when configured, never a hard failure without one). **2+ techniques** add `cross_validation` (verified) evidence.
  - **Open Redirect** — multi-technique `open_redirect_signals[]` fingerprint: `absolute`, `relative`, `protocol_relative`, `encoded`, `double_encoding`, each confirmed when two distinct payloads yield an off-host `Location` (decoding normalization in `_decoded_location`). **2+ techniques** add `cross_validation` (verified) evidence.
  - **SSTI Detection** — multi-engine evidence-only: `arithmetic_evaluation` per engine (jinja2/twig/freemarker/velocity/handlebars/smarty/erb) confirmed only when **two distinct math expressions** evaluate to the expected results; `{{ expr }}` syntax families deduped so one evaluation never claims multiple engines. **2+ engines** add `cross_validation` (verified) evidence.
- **Tests**: `tests/engine_tests.py` migrated-set assertion = 19 modules, 0-on-legacy count, runtime `scan()` contract tests for the 4 new scanners (the AST evidence-only guard auto-covers them); `tests/corpus.py` `_finding` legacy helper **deleted** — ssti_detected, lfi_ssrf, cors_open_redirect, scan_incomplete, scan_error converted to `_raw_finding`; golden baselines regenerated.
- **Validation**: `test_validation.py` 0 errors / 0 warnings; engine unit tests 0 errors / 0 warnings; golden regression `REGRESSION=0` (PASS=10, WARNING=6 — all explained band shifts); live scan runner + session save/replay on the Final Batch scanners' raw output `PASS` (exact parity, no diffs).
- **Docs**: `docs/TECHNICAL_DEBT.md` updated (0 unmigrated, behavioural-change log §3.11, Batch 6 reframed as legacy removal with migration items done); `project_docs/CHANGELOG.md` + `development_progress.txt` appended.

### v3.5.0 — 2026-08-01 — Engine v3 Migration Batch 4 Part 2 (SQL Injection / XSS Detection)
- **Migrated (15/19 now evidence-only)**: SQL Injection and XSS Detection joined the v3 engine pipeline. Each `scan()` now emits only raw evidence + test counters + fingerprints/metadata; status/severity/confidence/verification/execution-state are derived exclusively by `run_engine_pipeline` (`respect_existing=False`). The remaining 4 scanners (LFI, SSRF, Open Redirect, SSTI) stay on the legacy `decide()` path until the final batch.
- **Improved detection accuracy** (the batch's focus — repeated confirmation, no single-payload findings):
  - **SQL Injection** — multi-technique `sqli_signals[]` + `database` fingerprint: `error_based` (per-DB signature on the primary payload **reproduced with a second distinct payload**), `boolean_based` (true/false responses differ by ≥40 bytes / status / `<0.8` Jaccard similarity, **reconfirmed with the independent `'/**/OR/**/1=1-- -` comment-injection pair**), `time_based` (delay ≥ `max(baseline+4,6)s` from a 3-sample median baseline, **retry-consistent** with variance recorded). Every observation is structured `request_response` evidence (technique/matched_rule/database/reliability/reproducible/confirm_payload/timing/comparison). **2+ techniques** add `cross_validation` (verified) evidence; single-technique caps at `likely`/80.
  - **XSS Detection** — multi-context `xss_signals[]` + `reflected_params` fingerprint: `html` / `attribute` / `javascript` families, each tested per parameter with a primary payload **reconfirmed with a second distinct payload + an independent context regex**. Context patterns are executable-location-precise (`alert(` must sit inside the same tag/script), so escaped/echoed output (`&lt;script&gt;`) never matches; attribute context requires a literal quote breakout. **2+ contexts** add `cross_validation` (verified) evidence; encoded-probe decoding is `likely` support evidence only alongside a confirmed core context.
- **Tests**: `tests/engine_tests.py` migrated-set assertion (15 modules), 4-on-legacy count, runtime `scan()` contract tests for the 2 new scanners (the AST evidence-only guard auto-covers them); `tests/corpus.py` SQLi/XSS scenarios converted to `_raw_finding` (sqli_detected, xss_detected, mixed_corpus, scan_incomplete, scan_error) mirroring real multi-signal output; golden baselines regenerated.
- **Validation**: `test_validation.py` 0 errors / 0 warnings; engine unit tests 0 errors / 0 warnings; golden regression `REGRESSION=0` (PASS=9, WARNING=7 — all explained band shifts; sqli_detected and xss_detected moved WARNING→PASS to exact parity); live scan runner + session save/replay on `https://example.com` both `PASS` (exact parity, no diffs).
- **Docs**: `docs/TECHNICAL_DEBT.md` updated (4 unmigrated, behavioural-change log §3.10, Batch 6 backlog now lists the final LFI/SSRF/Open Redirect/SSTI batch); `project_docs/CHANGELOG.md` + `development_progress.txt` appended.

### v3.4.0 — 2026-08-01 — Engine v3 Migration Batch 4 Part 1 (evidence-only scanners)
- **Migrated (13/19 now evidence-only)**: CORS Configuration, CSRF Protection, and Host Header Injection joined the v3 engine pipeline. Each `scan()` now emits only raw evidence + test counters + fingerprints/metadata; status/severity/confidence/verification/execution-state are derived exclusively by `run_engine_pipeline` (`respect_existing=False`). The remaining 6 scanners (SQLi, XSS, LFI, SSRF, Open Redirect, SSTI) stay on the legacy `decide()` path until Batch 5.
- **Improved evidence normalization** (the batch's focus — multi-signal / multi-observation verification):
  - **CORS Configuration** — `cors_signals` fingerprint with independent per-origin signals: `wildcard_credentials`, `wildcard_origin`, `null_origin`, `origin_reflection` + `credentials_with_acao` (support, only alongside a core signal) + an OPTIONS `preflight_confirmed` probe. `Vary: Origin` absence is recorded as metadata (`vary_missing_origin`) rather than a separate `possible` evidence item — a `possible` item would cap the finding's confidence at 60 and undercut the multi-signal benefit. `tests_performed = 5`.
  - **CSRF Protection** — multi-observation per POST form: `no_token`, `cross_origin_accepted` (Origin/Referer gating probe), `token_not_enforced` (behavioural token-removal test), `token_enforced` (verified positive). No POST forms keeps the `verified` evidence + `NOT_APPLICABLE` execution state. Observations sorted issues-first.
  - **Host Header Injection** — multi-observation per test host: `body_reflection`, `redirect_location`, `generated_url` + `cache_poisoning_risk` (likely, gated on the injected host value appearing in the differing response + missing Vary Host/Origin, so a clean vhost'd site is not a false warning). `tests_performed = 4`.
- **Tests**: `tests/engine_tests.py` migrated-set assertion (13 modules), 6-on-legacy count, runtime `scan()` contract tests for the 3 new scanners (the AST evidence-only guard auto-covers them); `tests/corpus.py` scenarios converted to `_raw_finding` for the migrated modules (cors_misconfig, cors_open_redirect, host_header_csrf, mixed_corpus, clean_site); golden baselines regenerated.
- **Validation**: `test_validation.py` 0 errors / 0 warnings; engine unit tests 0 errors / 0 warnings; golden regression `REGRESSION=0` (PASS=7, WARNING=9 — all explained band shifts); live scan runner + session replay on `https://example.com` both `PASS` (no unexplained diffs).
- **Docs**: `docs/TECHNICAL_DEBT.md` updated (6 unmigrated, behavioural-change log §3.9); `project_docs/CHANGELOG.md` + `development_progress.txt` appended.

### v3.3.0 — 2026-08-01 — Engine v3 Migration Batch 3 (evidence-only scanners)
- **Migrated (10/19 now evidence-only)**: Technology Detection, Security.txt, Source Code Leaks, and Cookies Security joined Headers/TLS/DNS (Batch 1) and Open Ports/Sensitive Files/HTTP Methods (Batch 2) on the v3 engine pipeline. Each `scan()` now emits only raw evidence + test counters + fingerprints/metadata; status/severity/confidence/verification/execution-state are derived exclusively by `run_engine_pipeline` (`respect_existing=False`).
- **Improved evidence normalization** (the batch's focus):
  - **Cookies Security** — one evidence item per attribute (Secure/HttpOnly/SameSite/Prefix/Expiration/Domain/Path); `CookieAnalysis.issues` removed from `core/response_analyzer.py`, per-attribute data carried instead. Issue items sorted first so the v3 positive-observation rule never reclassifies a WARNING.
  - **Security.txt** — state machine in fingerprint `security_txt_state`: `missing`/`valid`/`accessible`/`invalid`/`malformed`; probes `/.well-known/security.txt` then `/security.txt`.
  - **Source Code Leaks** — 6 categories / 21 patterns; API Keys + Configuration Disclosure are `confirmed`-level evidence, Debug/Emails/Comments/Source Maps `likely`-level.
  - **Technology Detection** — one `verified` evidence per technology with provenance `raw_data = {technology, source, signal, detail}` via new `ResponseAnalyzer.detect_technology_fingerprints()`.
- **Tests**: `tests/engine_tests.py` migrated-set assertion (10 modules), 9-on-legacy count, runtime `scan()` contract tests for the 4 new scanners; `tests/corpus.py` scenarios converted to `_raw_finding` for the migrated modules (clean_site, xss_detected, sqli_detected, tls_strong, cms_wordpress, ports_http_sensitive); golden baselines regenerated.
- **Validation**: `test_validation.py` 0 errors / 0 warnings; engine unit tests 0 errors / 0 warnings; golden regression `REGRESSION=0` (PASS=7, WARNING=9 — all explained band shifts); live scan runner + session replay on `https://example.com` both clean (WARNING/PASS, no unexplained diffs).
- **Docs**: `docs/TECHNICAL_DEBT.md` updated (9 unmigrated, behavioural-change log §3.8); `project_docs/CHANGELOG.md` + `development_progress.txt` appended.

### v3.2.0 — 2026-08-01 — Engine v3 Migration Batch 2 (evidence-only scanners)
- **Migrated (6/19 now evidence-only)**: Open Ports, Sensitive Files, and HTTP Methods joined Headers/TLS/DNS on the v3 engine pipeline. Each `scan()` now emits only raw evidence + test counters + fingerprints/metadata; status/severity/confidence/verification/execution-state are derived exclusively by the engine pipeline (`run_engine_pipeline`, `respect_existing=False`).
- **Pipeline unchanged**: `Scanner → Evidence → Confidence → Verification → Severity → Correlation → Risk → Coverage → Assessment → Executive Summary`. No duplicated logic, no business logic inside scanners.
- **Behavioral change (documented)**: HTTP Methods dangerous-method findings are now `FAIL` (confirmed evidence) instead of the v2 scanner's manual `WARNING` override; the evidence was already `confirmed`-level, so the engine now applies its natural assessment. All other statuses/severities reproduce v2 exactly (regression gate green).
- **Corpus**: `tests/corpus.py` `ports_http_sensitive` now uses `_raw_finding` for the three migrated modules, mirroring real scanner output; golden baselines regenerated.
- **Tests**: `tests/engine_tests.py` updated — migrated-set assertion (6 modules), 13-on-legacy count, runtime `scan()` contract tests for Sensitive Files / HTTP Methods, and a new AST guard that fails any direct assessment-field assignment in migrated scanner sources.
- **Validation**: `test_validation.py` 0 errors / 0 warnings; engine unit tests 0 errors / 0 warnings; golden regression `REGRESSION=0` (PASS=3, WARNING=13 — all explained band shifts); live scan runner + session replay on `https://example.com` both `WARNING` (no unexplained diffs).
- **Docs**: `docs/TECHNICAL_DEBT.md` updated (13 unmigrated, behavioural-change log §3.7); `project_docs/CHANGELOG.md` + `development_progress.txt` appended.

### v3.1.0 — 2026-07-31 — Desktop GUI Redesign (enterprise product polish)
- **Rewritten**: entire `gui/` presentation layer from scratch — VS Code / Docker-style left icon rail (Overview/Scanner/History/Settings/About) replaces the old top-nav + wide sidebar; top bar carries the brand and a global "New Scan" action; JetBrains-style bottom status bar shows engine state, live progress and versions
- **Added**: single Scanner workspace with a state machine (setup → running → completed) replacing the separate Scan + Results pages; consolidated results are rendered by one shared `SummaryView` (risk meter, KPI strip, severity-coloured findings table) also reused by the History master–detail pane — removing the previous duplicated results layout
- **Added**: new design system — near-black navy + electric blue palette (light variant included), stroke-based dual-state programmatic icons, segmented controls, toggle switches, KPI cards, risk meter, toast notifications, status pills
- **Added**: `gui/version.py` as the single source of truth for `APP_NAME` / `GUI_VERSION` / `ENGINE_VERSION`; `gui/__init__.py` re-exports it
- **Removed**: `pages/dashboard_page.py`, `pages/results_page.py`, `widgets/stat_card.py` (replaced by Overview, Scanner workspace, KpiCard)
- **Kept**: services layer (Settings/History stores, ScanWorker engine bridge, log bridge) and the engine untouched; `module_started`/`module_finished` signals continue to carry module lifecycle data end-to-end
- **Docs**: README + PROJECT_STATE refreshed for the new IA
- **Validation**: `test_validation.py` 0 errors / 0 warnings; new GUI smoke test passes; ScanController cancel test passes; live ScanWorker pipeline test passes (report generated); offscreen + native launch verified on PySide6 6.11.1

### v3.0.0 — 2026-07-31 — Desktop GUI (PySide6)
- **Added**: `gui/` package — professional PySide6 desktop interface layered on the existing engine (no engine module modified)
- **Added**: Main window with top navigation (Dashboard/Scan/Results/Settings/About), left sidebar (Quick/Standard/Deep Scan), and a status bar (Ready/Scanning.../Completed/Failed + version)
- **Added**: Scan page with target, scan mode presets, thread count, timeout, HTML/PDF output, start/cancel, overall progress bar, current module, elapsed/remaining time, and live severity-colored log viewer
- **Added**: Dashboard cards from real data only (scanner status, version, total scans, last scan time, latest report, recent targets)
- **Added**: Results page with risk score, overall severity, confidence, modules completed, duration, coverage, and severity-colored findings table
- **Added**: JSON-backed settings (theme light/dark/system, defaults, report dir, auto-open report, remember last target) + scan history store
- **Added**: `ScanWorker`/`ScanController` — engine runs on a `QThread`; progress/log/module/completion events via Qt signals; the GUI never freezes
- **Changed**: `python main.py` now launches the GUI by default; `python main.py --cli` preserves the original terminal flow
- **Note**: GUI generates reports with `strict_validation=False` to work around the engine's "Skipped count does not match skipped findings" validation rejection on UNKNOWN-status findings (surfaced as warnings in the live log instead of silently dropping reports)

### v2.2.0 — 2026-07-30 — SSTI Scanner + CSRF v2 Rewrite
- **Added**: `scanners/ssti.py` — SSTI detection across 5 template engines (Jinja2/Twig, Freemarker, Velocity, ERB, Smarty), dual-payload cross-validation, registered as scanner #19
- **Rewritten**: `scanners/csrf.py` — v2 now extracts real POST form blocks, detects token fields, submits with/without token to verify server-side enforcement
- **Changed**: Registry updated (19 scanners, 12 page-level), decision engine STANDARDS expanded with SSTI Detection (CWE-1336, CRITICAL)
- **Docs**: README (18→19), CHANGELOG (v2.2.0), PROJECT_STATE updated

### v2.1.0 — 2026-07-29 — Jinja2 Templates & Thread Safety
- **Added**: `templates/report.html.j2` — Full HTML report template extracted from `reporter.py:build_html()` into Jinja2, making it editable without touching Python code
- **Added**: Jinja2 rendering in `build_html()` with graceful fallback to legacy inline template when Jinja2 not installed
- **Added**: `project_docs/SOP.md` — Standard Operating Procedure document
- **Fixed**: B9 — Confirmed `ScanResult.add_finding()` is already protected by `threading.Lock()`, regression test added
- **Fixed**: B13 — No mutable class-level state across all 18 scanners, `HostHeaderScanner.TEST_HOSTS` converted to tuple
- **Added**: Section 20 in `test_validation.py` — thread safety regression tests (B9/B13)
- **Docs**: Updated `BUGS.md`, `CHANGELOG.md`, `PROJECT_STATE.md`, `README.md`

### v2.0.0 — 2026-07-28 — Core Engine Overhaul
- **Added**: `core/verification_engine.py` — Multi-pass verification engine with 4 passes (INITIAL, CONFIRMATION, CROSS_VALIDATION, BEHAVIORAL), reflection/timing/status anomaly checks, evidence building from verification results
- **Added**: `core/response_analyzer.py` — Centralized response analysis: security header validation (10 headers with validation rules), cookie analysis (Secure/HttpOnly/SameSite), technology detection (16+ patterns: WordPress, Drupal, Laravel, React, Angular, Vue, Next.js, etc.), body normalization, Jaccard similarity, sensitive pattern extraction (API keys, AWS keys, private keys, JWT, passwords, secrets)
- **Added**: `core/correlation_engine.py` — Cross-finding correlation: 10 rules (xss_csp_bypass, xss_reflected_injection, cors_xss, cookie_hsts, info_disclosure, ssrf_lfi, host_header_cache, open_redirect_xss, csrf_xss, method_sensitive), confidence boosting (5-20 pts), severity escalation
- **Added**: `SmartPayloadSystem` in `scanners/base.py` — Adaptive payload selection by detected technology and param type, 5 encoding modes (url, double_url, unicode, hex, base64)
- **Enhanced**: `core/evidence.py` — 6 new `EvidenceType` values (BEHAVIOR_CHANGE, DOM_CHANGE, CONTENT_REFLECTION, SERVER_BEHAVIOR, CROSS_VALIDATION, CONSISTENCY_CHECK), `verification_pass` and `verification_method` fields on `Evidence`, 7 new builder methods (behavior_change, dom_change, content_reflection, server_behavior, cross_validation, consistency_check), fixed emoji in EvidenceBuilder.error()
- **Enhanced**: `core/finding.py` — New fields: correlation_escalated, correlation_findings, cross_validated, verification_passes, payload_evidence, response_fingerprint, baseline_fingerprint, technical_explanation, owasp_mapping, cwe_mapping, remediation_steps; enhanced confidence calculation with verification/correlation rewards; `run_correlation()` method on ScanResult
- **Enhanced**: `scanners/base.py` — VerificationEngine/ResponseAnalyzer integration, multi-pass verification methods (verify_multi_pass, add_verification_evidence, add_payload_evidence, capture_response_analysis), baseline request timing
- **Enhanced**: All 18 scanners — multi-pass verification with primary/confirm/cross payloads, smarter payload selection, better evidence capture, response analysis integration
- **Enhanced**: `main.py` — Correlation engine integration after all scanners complete, confidence boosts and severity escalation applied to findings
- **Enhanced**: `test_validation.py` — 60+ new tests covering verification engine, response analyzer, correlation engine, SmartPayloadSystem, new evidence types, new finding fields, base scanner enhanced methods
- **Validation**: 200+ checks pass (0 errors, 0 warnings)
- **Live Test**: Full pipeline verified against example.com — all 18 scanners execute without errors

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

**The Assessment Engine is feature-complete and stable (v4.12.0, SOP v4.0 Phase
4.4 COMPLETE).** Combined the pipeline holds `PARITY=0`, `REGRESSION=0`,
validation `0/0`, engine `0/0`, complete validation, confidence calibration,
assessment consistency, and improved executive assessment. Engine logic is now
**FROZEN** — no new engine features unless a verified defect requires it.

**Development priority shifts to product quality.** Work on the roadmap below,
one item at a time, only on explicit approval:

1. **Professional GUI redesign** — visual polish of the PySide6 desktop UI.
2. **Professional HTML report redesign** — commercial-grade `templates/report.html.j2`.
3. **Professional PDF report redesign** — production-grade PDF (WeasyPrint/ReportLab).
4. **User experience improvements** — scan workflow, status clarity, errors.
5. **Website improvements** — public-facing product site.
6. **Marketing assets** — screenshots, demo video, Gumroad product page.
7. **Final release preparation** — packaging, testing, docs.

**Continue only on approval.** Next unit of work (default suggestion): **Professional
HTML report redesign** (target: make the report visually marketable).

## Important Notes

### For AI Agents Continuing This Session

1. **ALWAYS start by reading** `PROJECT_STATE.md` (this file), `project_docs/development_progress.txt`, and `project_docs/CHANGELOG.md` to understand current state.

2. **Never rewrite entire files** — work incrementally, one phase/feature at a time.

3. **Run `python test_validation.py` after every change** — all 200+ checks must pass (0 errors, 0 warnings).

4. **Update `PROJECT_STATE.md` after every major implementation** — append new progress, never overwrite useful information.

5. **Two SSOT files exist**: `project_docs/development_progress.txt` (original) and `PROJECT_STATE.md` (root-level). Keep both in sync.

6. **Playwright is installed** (v1.61.0 + Chromium) but opt-in only via `use_js_crawler=True`.

7. **Host-level scanners always run** before page-level scanners. Base URL fallback exists for 0 useful pages.

8. **Decision engine v4.0** has all 18 scanners mapped with CWE, OWASP, CAPEC, MITRE, ASVS, severity, impact, CVSS, verify commands, and replay data.

9. **The scanner version** is in `core/finding.py` `get_statistics()` — bump it with every release.

10. **Backward compatibility is mandatory** — never remove or rename public methods/classes without aliasing.

11. **No feature bloat** — reject any feature that doesn't increase detection accuracy, user trust, or commercial quality.

12. **Emoji-free English-only** output in reports. Console output may still use emoji for Rich visual formatting.
