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

## Phase 5 — Scalability [IN PROGRESS]
- [ ] Fix thread safety in ScanResult.add_finding
- [ ] Improve scanner instance handling for parallel execution
- [ ] Improve concurrency model
- [ ] Improve internal APIs
- [ ] Improve code readability and maintainability
- [ ] Prepare for future plugin system
- [ ] Final architecture cleanup

## Future (Post-Phase 5)
- [ ] Async support (asyncio + aiohttp)
- [ ] Plugin system for third-party scanners
- [ ] Configuration file (YAML/JSON)
- [ ] Real PDF generation (ReportLab or WeasyPrint)
- [ ] Docker containerization
- [ ] CI/CD pipeline with automated testing
- [ ] Soft-404 detection in crawler
