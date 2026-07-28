# Known Bugs

## Fixed (Phases 1-4)

### B1 — Evidence Level Enum/String Comparison
- **Fixed in**: Phase 1
- **File**: `core/finding.py`
- **Fix**: Changed string comparison to enum member comparison (`is EvidenceLevel.EXPLOITED`)

### B2 — Decision Engine Severity Trust Logic
- **Fixed in**: Phase 1
- **File**: `core/decision_engine.py`
- **Fix**: WARNING status now uses `SEVERITY_BY_MODULE` map instead of hardcoded Severity.LOW

### B3 — HTML Escaping Broken
- **Fixed in**: Phase 1
- **File**: `core/reporter.py`
- **Fix**: `_escape_html` now produces valid `&amp;`, `&lt;`, `&gt;`, `&quot;`

### B4 — SSRF False Positives
- **Fixed in**: Phase 1 (baseline + metadata) + Phase 4 (multi-IP verification)
- **File**: `scanners/ssrf.py`
- **Fix**: Baseline comparison, AWS metadata patterns, error analysis, multi-IP confirmation

### B5 — Source Leaks False Positives
- **Fixed in**: Phase 1
- **File**: `scanners/source_leaks.py`
- **Fix**: 5 overly generic patterns replaced with 14 specific indicators

### B6 — Cookie HttpOnly Check Incorrect
- **Fixed in**: Phase 1
- **File**: `scanners/cookies.py`
- **Fix**: Case-insensitive attribute check for HttpOnly and SameSite

### B7 — generate_pdf Creates TXT Files
- **Fixed in**: Phase 1
- **File**: `core/reporter.py`
- **Fix**: Renamed to `generate_txt()`, kept backward-compatible alias

### B8 — Unused Modules
- **Fixed in**: Phase 3
- **Files**: `core/classifier.py`, `core/fingerprinter.py` (deleted)

### B9 — Thread Safety Issues on ScanResult
- **Status**: Open (to be fixed in Phase 5)
- **File**: `core/finding.py` (ScanResult.add_finding)
- **Issue**: `ScanResult.add_finding()` is called from multiple threads without locking.
  List append may not be atomic for the complex operations performed.
- **Impact**: Potential race conditions, lost findings under parallel load.

### B10 — Fake requests_sent Counter
- **Fixed in**: Phase 2
- **File**: `main.py`, `core/http_client.py`
- **Fix**: Real request tracking via TrackedSession.request_count

### B11 — Duplicate Form Parsing
- **Fixed in**: Phase 3
- **Files**: `core/form_crawler.py` (deleted, merged into crawler.py)

## Known Issues (Still Open)

### B12 — Missing requirements
- **File**: `requirements.txt`
- **Description**: The `cryptography` library is used in `tls.py` but listed as
  optional via try/except. The `beautifulsoup4` dependency has import error fallback.
  The `rich` import has fallback too.
- **Impact**: Partial functionality loss if dependencies missing.
- **Priority**: Low

### B13 — Thread Safety in Scanner Instance Attributes
- **File**: All scanners
- **Description**: Scanner instances that have mutable instance attributes
  (like SQLiScanner) are shared across threads in ThreadPoolExecutor, which
  could cause race conditions on instance state during parallel scan execution.
- **Impact**: Rare but possible data corruption during parallel scans.
- **Priority**: Low
