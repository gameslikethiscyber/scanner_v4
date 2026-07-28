# Changelog

## [1.8.0] - 2026-07-28

### Added
- **Report Branding**: Reporter now supports custom `logo_url`, `company_name`, `consultant_name`, `client_name`, and `report_id` via `branding` dict. HTML report header and footer use company name. Logo image, client/consultant info, and report ID displayed in header.
- **Detection Replay**: Every finding with verify_commands now shows a "Verification Replay" section in the HTML report with curl commands and a "Copy curl" button (clipboard API + fallback). `replay_data` populated automatically from evidence raw_data.
- **Branding Configuration**: `ScanConfig` extended with `company_name`, `consultant_name`, `client_name`, `report_id`, `logo_url` fields and `get_branding()` method.

### Changed
- **`core/reporter.py`**: `Reporter.__init__()` accepts optional `branding` dict. HTML header/footer use branded company name. Finding cards include replay section with copy-to-clipboard. JS added for clipboard copy with fallback.
- **`core/decision_engine.py`**: New `_populate_replay_data()` populates `finding.replay_data` from evidence raw_data. Called in `decide()` after verify commands.
- **`core/config.py`**: Added branding fields (`company_name`, `consultant_name`, `client_name`, `report_id`, `logo_url`) and `get_branding()` method.
- **`main.py`**: `generate_reports()` passes `config.get_branding()` to `Reporter()` constructor.
- **`core/finding.py`**: Scanner version bumped to 1.8.0, report version to 3.1.

### Quality
- All 160+ validation checks pass (0 errors, 0 warnings).
- Copy-to-clipboard works with both Clipboard API and fallback (`execCommand`).
- Replay data persists through `to_dict()` and JSON export.

## [1.7.0] - 2026-07-28

### Added
- **Attack Surface Inventory**: ScanResult expanded with `urls_discovered`, `urls_crawled`, `urls_skipped`, `useful_pages`, `forms_discovered`, `hidden_inputs`, `params_discovered`, `cookies_found`, `technologies`, `crawler_type`. All populated from real crawler diagnostics and piped through to reports.
- **PASS Finding Deduplication**: `ScanResult.add_finding()` now merges PASS findings by module name. `aggregate_safe_findings()` collapses all PASS findings into one per module with accumulated `occurrences`, `tests_performed`, and `affected_urls`.
- **Executive Summary**: Smart contextual summary generated from actual scan data — considers vulnerability count, verification levels, coverage, warnings, confidence. Replaces hardcoded templates.
- **Coverage Skip Reasons**: `get_coverage()` returns per-reason skip details. Displayed in reports with module names grouped by skip reason.
- **Finding Timeline**: Visual pipeline (Discovery -> Scanner -> Evidence -> Decision -> Risk -> Classification) shown in every finding card.
- **Collapsible HTTP Evidence**: Request/response details shown in expandable blocks. Raw headers, body snippets, matched patterns displayed.
- **Verification Badges**: Color-coded badges (Verified/Likely/Possible/Manual Review) in finding card headers.
- **Dark Mode**: Full dark mode support via `@media (prefers-color-scheme: dark)` CSS.
- **Print-friendly**: Collapsible sections auto-expand, no box shadows, page-break avoidance.
- **Export Formats**: Added `generate_json()`, `generate_markdown()`, `generate_csv()` to Reporter.
- **Report Format Choice**: User can choose HTML-only, HTML+JSON, or all formats (HTML/JSON/Markdown/CSV/TXT).

### Changed
- **`core/finding.py`**: ScanResult expanded with 20+ attack surface fields. `get_statistics()` includes `executive_summary`, `skip_reasons`, `verified_vulns`, `likely_vulns`, and all attack surface metrics. `get_coverage()` returns per-reason skip details. `add_finding()` now deduplicates PASS by module alone.
- **`core/reporter.py`**: Complete HTML template rewrite. Clean English headers (no emojis, no Arabic). Professional cards with timeline, collapsible evidence, verification badges. Attack surface shown in 3-column layout. Coverage section shows skip reasons. Dark mode CSS. Print-friendly. Version 3.0 report format.
- **`main.py`**: `crawl_target()` populates ScanResult with crawler diagnostics (visited URLs, skipped, useful pages, forms, hidden inputs, params, technologies, cookies). `run_scan_on_all_pages()` calls `aggregate_safe_findings()`. Report generation offers format selection.
- **`test_validation.py`**: 160 checks total (was 120). 40 new tests for PASS dedup, attack surface, executive summary, coverage skip reasons, JSON/Markdown/CSV exports, aggregate_safe_findings, report version.

### Fixed
- **URLs Crawled: 0** bug — No longer shows 0 when actual crawl happened. ScanResult now populated from real crawler diagnostics.
- **Duplicate PASS findings** — XSS Detection, SSRF Detection, Cookies etc. no longer appear multiple times.
- **Emoji-free output** — All report text is pure ASCII/UTF-8 without emoji characters.
- **Report language/direction** — Changed from `lang="ar" dir="ltr"` to `lang="en"`.

### Quality
- 160 validation checks pass (0 errors, 0 warnings).
- JSON, Markdown, CSV exports all tested.
- Dark mode, print mode, collapsible evidence all functional.
- Executive summary adapts to actual scan context.

### Added
- **Finding deduplication**: `Finding._dedup_key`, `merge()`, `occurrences`, `affected_urls`. `ScanResult.add_finding()` merges same-scanner+vulnerability findings automatically.
- **Risk score transparency**: `RiskCalculator` class with weighted formula (severity x confidence x verification x occurrences). Breakdown per finding with formula string.
- **Verification levels**: `Finding.verification_status` (verified/likely/possible/manual_review/unverified) derived from highest evidence level.
- **HTTP request/response evidence**: `EvidenceType.REQUEST_RESPONSE`, `EvidenceBuilder.request_response()`, `BaseScanner.capture_http_evidence()` for full HTTP trace capture.
- **Executive summary**: Contextual message in HTML reports based on highest severity found.
- **Attack surface summary**: URLs crawled, modules, requests, payloads, header/port tests in reports.
- **Risk score breakdown table**: Per-finding scores with severity, confidence, verification, occurrences.
- **21 new validation checks**: Deduplication, risk calculator, verification status, evidence types, to_dict completeness.

### Fixed
- **Host Header scanner false positives**: Now tests 4 host values; requires real reflection, redirect, or generated URL proof. Cache poisoning risk = WARNING, not FAIL.
- **Confidence calculation bug**: Error detection path only triggers on `EvidenceLevel.UNKNOWN` evidence, not on any evidence whose description contains "error".
- **Emoji print statements**: Replaced with ASCII-safe alternatives for Windows console compatibility.

### Changed
- **`scanners/host_header.py`**: Full rewrite — 4 test hosts, multi-factor evidence collection, proper status mapping.
- **`core/reporter.py`**: Report includes executive summary, attack surface, risk breakdown, verification status, occurrences, affected URLs in finding cards.
- **`core/finding.py`**: Added production fields, merge logic, dedup in add_finding, verification status.
- **`core/decision_engine.py`**: Added `RiskCalculator` class.
- **`core/evidence.py`**: Added `REQUEST_RESPONSE` evidence type and builder method.
- **`scanners/base.py`**: Added `capture_http_evidence()` helper.
- **`test_validation.py`**: 120 checks total (was 99).

### Quality
- 120 validation checks pass (0 errors, 0 warnings).
- 21 new production-quality tests.
- All scans, crawlers, reporters, decision engine produce consistent results.

## [1.4.0] - 2026-07-28

### Fixed (Critical)
- **Cookie HttpOnly/SameSite detection**: Replaced non-existent `has_nonstandard_attr()` with `cookie._rest` dict lookup (was crashing with AttributeError on every request).
- **CORS severity escalation**: Replaced string comparison (`"medium" > "none"` = False) with integer weight map via `_escalate_to()`. Severity now correctly escalates from NONE to MEDIUM/HIGH/CRITICAL.
- **Decision engine impact map**: Keys now match actual scanner module names (`'XSS Detection'` not `'XSS'`). Impact scores now apply correctly to all findings.

### Added
- **Thread safety**: `ScanResult.add_finding()` now uses `threading.Lock` for safe parallel collection.
- **Scanner registry API**: `get_scanner_by_name()`, `is_host_level()`, `is_page_level()` for plugin-style discovery.
- **SSRF POST support**: SSRF scanner now tests POST parameters in addition to GET.
- **FIPS compliance**: `hashlib.md5(usedforsecurity=False)` for FIPS-enforced Python builds.
- **cryptography < 41.0 compat**: Fallback from `not_valid_after_utc` to `not_valid_after`.

### Changed
- **SensitiveFilesScanner**: Moved from page-level to host-level (was running 13 file checks per page).
- **Crawler baseline**: Moved outside parameter loop in boolean-based SQLi check (fewer HTTP requests).
- **Registry name map**: Static dict literal replaces wasteful runtime scanner instantiation.

### Quality
- 25 unused imports removed across 18 files.
- Duplicate `add_evidence_with_snippet` removed from sqli.py (uses inherited).
- `doseq=True` added to `urlencode` for correct multi-value parameter encoding.
- Removed unused `ec`, `field`, `json`, `requests` imports across files.
- 96 validation checks pass (0 errors, 0 warnings).

## [1.3.0] - 2026-07-28

### Added
- **Multi-step verification for SQLi**: After detecting an error/time/boolean signal, sends a different payload to confirm. Comment-injected payloads (`'/**/OR/**/1=1-- -`) for boolean confirmation.
- **Reflection verification for XSS**: Two-phase approach — confirms payload is reflected in response before reporting. Uses different verify payloads.
- **Adaptive LFI depth**: `_guess_depth()` calculates traversal depth from URL path structure (3-8 levels). Error-based detection for PHP inclusion errors.
- **CORS trusted origin whitelist**: `set_trusted_origins()` allows users to whitelist legitimate origins. OPTIONS pre-flight request check.
- **Multi-IP SSRF verification**: Confirms SSRF with a second internal IP (`127.0.0.2`, `0.0.0.0`) before reporting.
- **`add_evidence_with_snippet()` in BaseScanner**: Captures response body snippets (200 chars), response headers, and timing info.
- **CVSS 3.1 vector generation**: `decision_engine._calculate_cvss()` now generates proper vector strings (AV/AC/PR/UI/S/C/I/A).
- **`cvss_vector` attribute in Finding**.

### Changed
- **Confidence scoring**: Switched from sum accumulation to weighted-average calculation. Base confidence starts at 50 (was 0). Uses evidence `weight` property.
- **CORS severity tiers**: wildcard+credentials=CRITICAL, origin reflection=HIGH, null=MEDIUM. Status changed from WARNING to FAIL.
- **SQLi severity**: Error-based=CRITICAL, time-based=HIGH, boolean-based=MEDIUM (was always CRITICAL).
- **XSS payload set**: Removed URL and SVG contexts (high FP, low impact).

### Quality
- All 5 major scanners now use multi-step verification to reduce false positives.
- Median baseline time for time-based detection (more robust than mean).
- Response snippets and timing in evidence `raw_data` for better forensics.
- 96 validation checks pass.

## [1.2.0] - 2026-07-27

### Added
- **Scanner Registry** (`scanners/registry.py`): Centralises all 18 scanner
  imports and classifies them as host-level or page-level. Adding a new
  scanner requires only one import + one list entry.
- **Configuration System** (`core/config.py`): `ScanConfig` dataclass with
  `max_pages`, `max_workers`, `request_timeout`, `user_agent` and more.
  `SeaScanner` accepts an optional `config` parameter.
- **Logging**: Python `logging` writes to `logs/scan_<timestamp>.log` at
  DEBUG level, coexisting with existing rich console output.

### Changed
- `scanners/base.py`: Added `get_params()`, `inject_payload()`, and
  `post_data_with_payload()` methods — previously duplicated in 5 scanners.
- `core/crawler.py`: Added `extract_post_forms()` method, replacing
  `FormCrawler` class.
- `main.py`: Uses Scanner Registry instead of 18 individual imports; uses
  `ScanConfig`; uses `Crawler.extract_post_forms()`.
- `scanners/sqli.py`, `xss.py`, `lfi.py`, `ssrf.py`, `open_redirect.py`:
  Removed duplicate `get_params()` and `inject_payload()` — now inherited
  from `BaseScanner`.

### Removed
- `core/classifier.py`: Dead code — `Classifier` class never imported.
- `core/fingerprinter.py`: Dead code — `Fingerprinter` class never imported.
- `core/form_crawler.py`: Merged into `core/crawler.py`.

### Architecture
- 31 Python source files (down from 33, 3 removed, 3 added across phases).
- ~250 lines of dead/duplicate code eliminated.
- Zero duplicated URL parameter parsing across the codebase.
- Single source for scanner classification.
- Centralized configuration for key parameters.

## [1.1.0] - 2026-07-27

### Added
- Shared HTTP session (`core/http_client.py`)
- Response cache with LRU eviction

### Changed
- All 18 scanners share one `TrackedSession` via SeaScanner
- Real request tracking replaces fake `+=5` counter
- Crawler: 36 skip extensions (was 14)
- Removed per-scanner session creation and UA overrides

### Performance
- Single connection pool (was 19 separate pools)
- ~300 fewer DNS resolutions per scan

## [1.0.1] - 2026-07-27

### Fixed
- Evidence enum-vs-string comparison (confidence now works correctly)
- HTML escaping (valid HTML entities)
- SSRF false positives (baseline comparison + metadata patterns)
- Source leaks false positives (specific indicators)
- Cookie security flag detection (case-insensitive)
- Decision engine severity for WARNING findings
- CWE/OWASP maps matching actual scanner names
- 35 bare `except:` blocks replaced with typed exceptions

## [1.0.0] - 2026-07-27

### Added
- Initial project documentation in `project_docs/`
