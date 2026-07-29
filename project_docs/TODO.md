# TODO List

## Phase 1 — Critical Bug Fixes [COMPLETED]
- [x] Fix evidence level enum-vs-string comparison in finding.py:135-144
- [x] Fix HTML escaping in reporter.py (replace & with &amp;)
- [x] Fix cookie HttpOnly check — use case-insensitive attribute lookup
- [x] Fix source leaks scanner patterns — reduce false positives
- [x] Fix SSRF scanner false positives — add baseline validation
- [x] Fix decision engine severity trust logic — use module map for WARNING
- [x] Fix generate_pdf() naming — renamed to generate_txt()
- [x] Replace bare `except:` blocks across all files
- [x] Fix DecisionEngine CWE/OWASP maps to match actual scanner names

## Phase 2 — Performance Improvements [COMPLETED]
- [x] Introduce shared requests.Session across all scanners
- [x] Remove duplicated HTTP requests (unified import pattern)
- [x] Add response caching (LRU cache, 200 entries, 60s TTL)
- [x] Improve connection reuse (single TrackedSession)
- [x] Optimize crawler performance (49 skip extensions, skip content types)
- [x] Skip unnecessary static assets (images, fonts, CSS, JS, videos)
- [x] Avoid scanning duplicate content (visited set in crawler)
- [x] Reduce unnecessary network traffic (36→49 skip extensions)

## Phase 3 — Architecture Improvements [COMPLETED]
- [x] Remove dead code (classifier.py, fingerprinter.py deleted)
- [x] Merge duplicated logic (form_crawler → crawler)
- [x] Merge duplicated form parsing
- [x] Extract get_params() and inject_payload() into BaseScanner
- [x] Introduce Scanner Registry (scanners/registry.py)
- [x] Introduce Configuration System (core/config.py)
- [x] Improve logging (logging module + file output)
- [x] Improve project organization
- [x] Reduce code duplication
- [x] Fix fake requests_sent counter (TrackedSession)

## Phase 4 — Detection Quality [COMPLETED]
- [x] Improve SQLi validation (multi-step verification)
- [x] Improve XSS validation (reflection verification)
- [x] Improve SSRF validation (multi-IP confirmation)
- [x] Improve LFI validation (adaptive depth + error-based detection)
- [x] Improve CORS detection (trusted origins + OPTIONS pre-flight)
- [x] Improve evidence collection (snippets, headers, timing)
- [x] Improve confidence scoring (weighted-average)
- [x] Improve risk scoring (CVSS 3.1 vector generation)
- [x] Add multi-step validation (all major scanners)

## Phase 5 — Scalability [PENDING]
- [ ] Fix thread safety in ScanResult.add_finding
- [ ] Improve scanner instance handling for parallel execution
- [ ] Improve concurrency model
- [ ] Improve internal APIs
- [ ] Improve code readability and maintainability
- [ ] Prepare for future plugin system
- [ ] Final architecture cleanup

## Phase 6 — Core Engine Overhaul [COMPLETED]
- [x] Create `core/verification_engine.py` — Multi-pass verification engine with reflection, timing, and status code anomaly detection
- [x] Create `core/response_analyzer.py` — Centralized response analysis with security headers, cookies, technology detection, body normalization, similarity scoring, and sensitive pattern extraction
- [x] Create `core/correlation_engine.py` — Cross-finding correlation engine with 10 rules (xss_csp_bypass, cors_xss, cookie_hsts, etc.), confidence boosting, and severity escalation
- [x] Enhance `core/evidence.py` — 6 new EvidenceType values (BEHAVIOR_CHANGE, DOM_CHANGE, CONTENT_REFLECTION, SERVER_BEHAVIOR, CROSS_VALIDATION, CONSISTENCY_CHECK), verification metadata fields, 7 new builder methods
- [x] Enhance `core/finding.py` — New fields (correlation_escalated, verification_passes, payload_evidence, response_fingerprint, baseline_fingerprint, technical_explanation, owasp_mapping, cwe_mapping, remediation_steps), enhanced confidence calculation with verification/correlation rewards
- [x] Rewrite `scanners/base.py` — SmartPayloadSystem with adaptive payload selection and encoding (url, double_url, unicode, hex, base64), VerificationEngine/ResponseAnalyzer integration, evidence capture helpers
- [x] Update all 18 scanners with multi-pass verification, better evidence, and smarter payloads
- [x] Integrate correlation engine in main.py (runs after all scanners complete)
- [x] Update test_validation.py with 60+ new tests for all new engines and features
- [x] All 200+ validation checks pass with 0 errors and 0 warnings
- [x] Live test against example.com confirms full pipeline works end-to-end

## Future (Post-Phase 6)
- [ ] Async support (asyncio + aiohttp)
- [ ] Plugin system for third-party scanners
- [ ] Configuration file (YAML/JSON)
- [ ] Real PDF generation (ReportLab or WeasyPrint)
- [ ] Docker containerization
- [ ] CI/CD pipeline with automated testing
- [ ] Soft-404 detection in crawler
