# Changelog

## [4.13.0] - 2026-08-03 - Professional GUI Redesign (presentation-only)

**Product-quality release for the frozen engine (v4.12.0) and alongside the
professional HTML report.** The PySide6 desktop GUI was redesigned to a
commercial-grade design system that matches the HTML report's visual language
(indigo accent, report-aligned severity scale). Presentation only — no scanner,
assessment, or data code changed; engine imports remain confined to
`gui/services/scan_worker.py`.

### Added
- **New QSS design system** (`gui/resources/styles.py`): full rewrite — flat
  surfaces, indigo accent (`#4F46E5`), report-aligned severity scale
  (`#E5484D`/`#F76B15`/`#F5A623`/`#2E9E5B`/`#0E9F6E`), two complete palettes
  (**dark** window `#0B1220` / surface `#101A2E`; **light**), objectName
  selectors for buttons/cards/KPI cards/risk meter/pills/badges/segmented/
  stepper/tables/log view/toasts/scrollbars/menus/tooltips/status bar.
- **Palette architecture**: `Palette` dataclass extended with rail/header/
  statusbar/soft/accent/severity fields; helpers `palette_for/qcolor/
  severity_color/severity_soft_color/status_color/tier_color/
  tier_from_severity/build_qss/apply_theme`.
- **Premium widget treatment**: `KpiCard` now renders icons in an accent-soft
  chip (`kpiIcon`, 34px); rail navigation icons recolor to `subtext` (idle) /
  `accent` (active) on theme switch and navigation; brand logo recolors with
  the theme.
- **`tools/gui_visuals.py`** — headless (offscreen) smoke + screenshot harness:
  renders every page (overview, scanner setup/running/completed, history,
  settings, about) in dark and light with seeded throwaway history, asserts
  palette propagation, writes PNGs to `reports/screenshots/gui/`.
- **Removed dead code** `gui/pages/scan_page.py` (393-line duplicate of the
  active `scanner_page.py`; no live imports).

### Fixed
- `summary.py` `_status_color` hardcoded `DARK` — now uses the active palette
  (`status_color(severity, palette)`), so severity/status colours follow theme.
- `overview_page.py` failed to push the palette to its `RiskMeter` — fixed.
- `settings_page.py` toggle switches never received the palette — they now get
  `apply_palette`, so the on/off switches follow dark/light.
- `scanner_page.py` log views (running + completed) now receive the palette;
  fixed the duplicate auth page bug (the token/bearer/JWT page was built twice,
  overwriting shared widgets — now built once and reused).

### Gates (all green)
- Validation `0/0`, engine `0/0`, `REGRESSION=0` (PASS=10, WARNING=6), `PARITY=0`.
- GUI smoke checks all pass (palette propagation across all pages; both themes
  render; offscreen capture of all 10 views).

## [4.12.1] - 2026-08-03 - Professional HTML Report Redesign (presentation-only)

**Product-quality release for the frozen engine (v4.12.0).** The HTML report
was redesigned to commercial-grade / enterprise quality. No scanner, assessment,
or data code changed — presentation only (`templates/report.html.j2` full
rewrite + CSS-class/markup edits in `core/reporter.py`).

### Added
- Executive-dashboard header: verdict hero, KPI cards, conic-gradient severity
  donut, risk ring gauge (pure CSS — no charting library, offline-safe).
- Light / dark / system themes (`data-theme` + `prefers-color-scheme`) with a
  persisted toggle; sticky TOC sidebar; back-to-top.
- Native `<details>/<summary>` collapsible evidence (no JS required);
  `@media print` forces all collapsible blocks open and hides chrome, so the
  PDF/print output carries full detail.
- Inline stroke-SVG icons for the attack-surface section (emojis removed).
- `tools/report_sample.py` + `tools/report_visuals.py` harnesses for producing
  deterministic sample reports (through the production `generate_html` path)
  and Playwright screenshots / A4 print PDFs.
- `project_docs/html_report_redesign.md` — full before/after + design-system
  documentation.

### Notes
- Report output contains no literal `&` (inline JS uses nested `if`, separators
  are literal UTF-8) — satisfies the `test_validation.py` escaping contract.
- Performance: `generate_html` ≈ 43.7 ms/report, ~85 KB HTML.

### Gates (all green)
- Validation `0/0`, engine `0/0`, `REGRESSION=0` (PASS=10, WARNING=6), `PARITY=0`.

## [4.12.0] - 2026-08-03 - Assessment Consistency, Executive Assessment & Engine Freeze (SOP v4.0 Phase 4.4)

**Assessment Engine is now feature-complete and declared stable.**
This is the stable release checkpoint for the completed engine architecture.
Combined, the pipeline holds `PARITY=0`, `REGRESSION=0`, validation `0/0`,
engine `0/0`, with complete validation, confidence calibration, assessment
consistency, and improved executive assessment. From this release on,
development priority shifts to **product quality** (GUI, reports, UX, website,
marketing, release prep). No additional engine features will be introduced
unless they fix a verified defect.

### Added
- **Warning-aware assessment** in `core/assessment_engine.py`: warning findings
  are now propagated into the `Assessment` summary and the assessment-confidence
  factors. A scan with `warning_count > 0` but **no confirmed vulnerabilities**
  and no failed/verification skips applies a bounded `warning_uncertainty` penalty
  (`min(10, warning_count * 3)`), so a clean-but-warned scan is no longer scored
  at 100% confidence without explanation.
- **`Severity.INFO` assessment tier** — `_severity_tiers()` now emits an
  `INFO` / "Warning only" tier for warning-only outcomes (no confirmed
  vulnerabilities), distinct from a fully clean `NONE` tier, so the overall
  verdict is honest when only warnings exist.
- **Verdict threshold tuning**: the overall-verdict ladder now requires
  materially higher evidence before escalation (critical-with-verified-evidence
  at `risk_score >= 80` was 70; high-with-two-verified at `>= 60` was 50;
  high-with-material-confidence at `>= 45` was 40; medium at `>= 35` was 30;
  a warning-only branch resolves to `INFO`). The verdict no longer over-states a
  finding's severity from a borderline risk score.
- **Warning-only executive summary** (`core/executive_summary.py`): a scan with
  warnings but no confirmed vulnerabilities now gets dedicated `_prose`,
  `_key_findings` and `_positive_highlights` text ("X warning(s) flagged, no
  confirmed vulnerabilities, Y checks passed"), instead of falling through to the
  "no vulnerabilities / all clear" prose. `has_vulns` is threaded through the
  helpers to drive the correct phrasing throughout.

### Changed
- `AssessmentSummary` and assessment-confidence now consistently receive the
  same `warning_count` (previously it was only read for the summary count; the
  confidence path reused `warning_findings` internally). Assessment output is
  internally consistent.

### Parity & Gates
- `PARITY=0` (frozen `tests/fixtures/calibration/parity_baseline.json`).
- `REGRESSION=0` (PASS=10, WARNING=6, unchanged).
- `python test_validation.py`: 0 errors / 0 warnings.
- `python -m tests.engine_tests`: 0 errors / 0 warnings.

### Scope freeze
- **Assessment pipeline is feature-complete for this release.**
- Future work is gated to **defect fixes only**; roadmap moves to product
  quality (GUI redesign, HTML/PDF report redesign, UX, website, marketing,
  final release prep) — see `PROJECT_STATE.md` "Remaining Tasks" / "Next".

## [4.11.0] - 2026-08-02 - Confidence Normalization (SOP v4.0 Phase 4.3)

Implemented confidence normalization under the `SEA_CALIBRATION` feature flag.
When the flag is OFF (default), the engine is byte-identical to v4.9.0
(`REGRESSION=0`, `PARITY=0`, validation `0/0`, engine `0/0`). When the flag is
ON, the calibrated profile reconciles caps with verification bands and blends
`evidence_quality` into the confidence base.

**No consumer-visible change in default mode.** Calibration is gated and inert.

### Added
- `CALIBRATED_CONFIDENCE` dict in `core/assessment_config.py` — normalized caps:
  CAP_VERIFIED 90→95, CAP_CONFIRMED 85→95, CAP_LIKELY 75→80, CAP_POSSIBLE 60→55;
  EVIDENCE_QUALITY_WEIGHT=1.0.
- `confidence_engine._profile()` — selects frozen vs calibrated dict based on
  `feature_flags.enabled()`. Instance path is gated; class constants remain frozen
  for legacy callers.
- `confidence_engine.compute()` — when calibrated: blends `evidence_quality` into
  base (`quality_base = eq; base = max(legacy_base, quality_base)`), applies
  normalized caps.
- `tests/calibration_benchmark.py` → `tests/fixtures/calibration/calibration_benchmark.json`
  — Before/After comparison across 8 canonical scenarios + scan-level deltas.
- `project_docs/calibration_phase3.md` — full rationale, per-scenario deltas, cap
  reconciliation table.

### Changed
- **Confirmed evidence** verifies as **likely** (up from possible) when calibrated —
  the C1 fix: raised cap and evidence_quality blend lift confidence from 70→85.
- **Verified evidence** now reaches confidence 90→95, matching 'confirmed'
  verification band threshold.
- **Scan risk_score** rises 38→65 under calibration (higher confidence on
  high-severity findings = higher risk weight).
- **C2 fix**: `evidence_quality` (previously unused) now directly lifts confidence
  when the flag is ON. Rich evidence (payload + snippet + verification passes)
  produces higher confidence.

### Documented
- `project_docs/calibration_phase3.md` (architecture + cap reconciliation +
  per-scenario table + rationale for each adjustment).

## [4.10.0] - 2026-08-02 - Engine Calibration Foundation (SOP v4.0 Phase 4.2)

Behavioral-parity foundation for Phase 4 confidence normalization. Introduced the
single source of truth for engine constants and a gated instrumentation path so
the upcoming calibration is a one-place change backed by a frozen snapshot.

**No consumer-visible change**: confidence, risk, severity, report, and
assessment output are byte-identical to the v4.9.0 baseline
(`PARITY=0`, `REGRESSION=0`, validation `0/0`, engine `0/0`).

### Added
- **`core/assessment_config.py`** — centralized single source of truth for all
  engine constants: `EVIDENCE`, `CONFIDENCE`, `VERIFICATION`, `SEVERITY`, `RISK`,
  `COVERAGE`, `ASSESSMENT` (+ helper functions and band/cap tables).
- **`core/feature_flags.py`** — `SEA_CALIBRATION` gate (default `off`, inert) with a
  `CalibrationCollector` that records per-finding/scan observations to
  `SEA_CALIBRATION_DIR` (default `reports/calibration`) when set to `report`.
- **`tests/calibration_capture.py`** — deterministic canonical scenario snapshot
  → `tests/fixtures/calibration/parity_baseline.json`.
- **`tests/calibration_parity_test.py`** — parity guard that recomputes and
  asserts the frozen numbers are unchanged (`PARITY=0`).

### Changed
- Engines now import constants from `assessment_config` (identical values, no
  behavior change): `confidence_engine`, `evidence_engine`, `verification_engine`,
  `severity_engine`, `risk_engine`, `coverage_engine`, `assessment_engine`,
  `decision_engine.RiskCalculator`, `pipeline` (report map).
- `core/pipeline.py` — added gated instrumentation hooks (finding + scan records)
  that are inert unless the flag is on.
- **RiskCalculator** now reads the shared `RISK` config (resolves a latent drift
  vs `RiskEngine`; live paths use `RiskEngine` so no numeric change).

### Documented
- `project_docs/calibration_foundation.md` (architecture + constants + flags +
  snapshot + report); `project_docs/calibration_audit.md` (P4.1 findings).

## [4.9.0] - 2026-08-02 - Scanner Quality Pass (SOP v4.0 Phase 3.10)

Final scanner-quality pass before Phase 4. Four high-value detection-accuracy
improvements with deterministic benchmarks + validation; the remaining five
scanners audited and formally documented as unchanged.

### Improved
- **Sensitive Files** (`scanners/sensitive_files.py`): removed benign public
  files from the exposure catalogue (robots.txt, README, LICENSE, package.json,
  sitemap.xml, Makefile, .gitignore) and added a `_raises_wrapper_page` guard so
  a 200-with-HTML-"Not Found" custom error page is never a false positive.
  Benchmark `benchmarks/sensitive_files_benchmark.py`: Before 3 TP / 1 FP / 1 TN
  (precision 75%) → After 3 TP / 0 FP / 0 FN / 2 TN (100% / 100%).
- **HTTP Methods** (`scanners/http_methods.py`): allowance is now **2xx executed
  or 401 auth-gated only**; 3xx redirects, 404/403/405 and 5xx no longer signal a
  permitted method. Dangerous set = PUT/DELETE/TRACE/CONNECT/PATCH/PURGE, driving
  dynamic `http_methods_confidence` + `detection_methods`. Benchmark
  `benchmarks/http_methods_benchmark.py`: 4 TP / 1 FP (302) / 1 TN → 4 TP / 0 FP /
  0 FN / 2 TN (100% / 100%).
- **Headers Security** (`scanners/headers.py`): eliminated duplicate issue
  emission (weak CSP was reported twice). Single-source, exact-once fingerprint
  via `header_present` / `header_missing` / `header_issues` / `header_confidence`;
  missing-header severity from `MISSING_SEVERITY`. Benchmark
  `benchmarks/headers_benchmark.py` measures negative-only evidence terms.
- **Source Code Leaks** (`scanners/source_leaks.py`): ambient/informational
  categories (**Emails, Comments, Debug Information, Source Maps**) are emitted
  only alongside a real confirmed leak (API Keys / Configuration Disclosure);
  confirmed leaks dedupe to exactly one category each. Added legitimate
  AWS/Azure/AMAZON access-key + `AKIA` patterns to close a FN. Benchmark
  `benchmarks/source_leaks_benchmark.py`: Before 0 TP / 4 FN (fixtures) →
  After 4 TP / 0 FP / 0 FN / 2 TN (100% / 100%).

### Documented unchanged (audited, rationale in `project_docs/scanner_quality_report.md`)
- Technology Detection (`tech_detect.py`): signature-match detection emits only
  `verified` evidence; no local FP/FN accuracy model to improve.
- DNS Security (`dns_scanner.py`): network-bound on live resolver.
- TLS/SSL Security (`tls.py`): network-bound handshake + cert chain; grading
  already severity-correct.
- Open Ports (`ports.py`): network-bound TCP connect with timeout; FP-free.
- Host Header Injection (`host_header.py`): already the most hardened (multi-
  observation body/redirect/URL/cache-poisoning-with-Vary gate).

### Validation (new sections, zero failures)
- `test_validation.py` §§42–46 now cover the improved cookies, sensitive files,
  HTTP methods, headers, and source-leak scanners. **0 errors / 0 real failures.**

### Regression
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: **REGRESSION=0** (PASS=10, WARNING=6).

Gates: **validation 0 errors / 0 real failures, engine 0/0, regression REGRESSION=0**.
Phase 4 is gated on review of `project_docs/scanner_quality_report.md`.

## [4.8.0] - 2026-08-02 - Cookies Security Detection Accuracy (SOP v4.0 Phase 3.9)

### Added
- **Structured cookie-issue detection** in `scanners/cookies.py`, replacing the purely informational attribute listing with issue-driven detection. For **session-recognizing** cookies (name token match against `SESSION_FRAGMENTS` like `sid`/`session`/`auth`/`token`/`jwt`/`asp`, or any `__Host-`/`__Secure-` prefixed cookie) the scanner now reports:
  - `missing_secure` — no `Secure` flag (session cookies: high; prefixed cookies: **critical**);
  - `missing_httponly` — JS-readable session token (XSS exposure);
  - `missing_samesite` / `samesite_none` — no CSRF mitigation / explicit `SameSite=None`;
  - `prefix_misuse` — a `__Host-` cookie that also sets a `Domain` attribute (illegal);
  - `persistent_session` — a session cookie whose expiry is > `PERSISTENCE_WINDOW_DAYS` (7 days) in the future;
  - `broad_domain` — a `Domain` at a broad / top-level scope (e.g. `Domain=com`);
  - `missing_path` — session cookie without an explicit `Path`.
- **Raw `Set-Cookie` supplement** (`_raw_cookies`): the requests cookiejar silently **drops** cookies whose scope it considers invalid (most notably `Domain=com` — a top-level public suffix). `_raw_cookies` parses `resp.raw.headers.getlist('Set-Cookie')` directly so those policy violations are never missed (closes the v3 false-negative where `/broad_domain` was invisible).
- **Session vs asset cookie discrimination**: a non-session, non-prefixed cookie (`visitor`, `pref`, …) with weak flags is deliberately **not** flagged, so preference/analytics cookies don't become false positives.
- **Dynamic confidence** (`_confidence`): a reproducible `0–100` score derived from the number and severity of cookie issues (`critical`/`high`/`medium`/`low`), stored as `cookie_confidence` — `0` when every cookie is hardened.
- **`benchmarks/cookies_benchmark.py`** — deterministic local fixture (5 vulnerable + 3 clean endpoints) → `reports/cookies_benchmark.json`.

### Improved
- Each issue is emitted as `likely` evidence with `matched_signal`/`type`/`severity`/`reliability=high`/`reproducible=True`; the `cookie_issues` fingerprint carries `type`/`name`/`severity`/`recommendation` and `cookies` describes each jar cookie (`secure`/`httponly`/`samesite`/`prefix`/`domain`/`path`/`expires`/`session_like`).
- Jam-wide attributes (Secure/HttpOnly/SameSite) are still reported as `verified` evidence when present, preserving report richness.

### Benchmark (Phase 3.9)
- Local fixture: `/unsecure_session`, `/no_httponly_session`, `/prefix_misuse`, `/persistent_session`, `/broad_domain` (vulnerable) VS `/good_session`, `/asset_nosession`, `/clean_batch` (clean).
- **Before (v3):** `detection rate 0%` — the scanner emitted attribute evidence only (Secure missing → `likely`), never set `cookie_issues`. All 5 vulnerable endpoints were false negatives.
- **After:** **detection rate 100% (5/5), 0 false positives, 0 false negatives, 3 true negatives** — `missing_secure`, `missing_httponly`, `prefix_misuse`+`missing_secure`, `persistent_session`, and `broad_domain` (via raw header) all detected; `/good_cookie`, `/asset_nosession` and `/clean_batch` correctly **not** flagged.

### False-positive analysis
- Non-session asset/preference cookies with weak flags are not flagged (a `visitor=…; Path=/` cookie is not a secured-session break).
- A fully hardened cookie (`Secure; HttpOnly; SameSite=Strict; Path=/`) yields zero issues and `cookie_confidence = 0`.
- Broad-domain detection is scoped to raw, jar-invisible casualties rather than re-deriving the jar's record, avoiding double-counting.

### Regression report
- `test_validation.py`: **0 errors / 0 warnings** — new §42 (Cookies Security Detection Accuracy) covers: missing Secure, missing HttpOnly, `__Host-` prefix misuse (critical), far-future persistence, broad-domain from raw Set-Cookie (jar blind spot), `__Host-`+`Domain` prefix misuse, `SameSite=None`, hardened-cookie clean (no FP), asset cookie not flagged, dynamic-confidence scaling.
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: **REGRESSION=0** (PASS=10, WARNING=6, unchanged baseline).

Residual limitation: a top-level `Domain` is only treated as broad when it is a bare single-label public suffix; an over-broad but well-formed domain (`example.com` vs `example.org`) is reported on presence of scope intent rather than a full public-suffix-list membership check.

## [4.7.0] - 2026-08-02 - CORS Configuration Detection Accuracy (SOP v4.0 Phase 3.8)

### Added
- **Cross-method confirmation** (`_probe` + `PROBE_METHODS`) in `scanners/cors.py`: every origin is probed with **both GET and POST** so a policy that reflects an origin only on a specific method is never missed — this fixes the real v3 **false-negative** where an endpoint allowed an origin only on POST/OPTIONS.
- **Credentials-aware scoring**: a wildcard / reflection combined with `Access-Control-Allow-Credentials: true` is `confirmed` (authenticated data readable); the identical policy **without** credentials is downgraded to `likely` — a deliberate **false-positive reduction** (a credential-less broad origin is degenerated, not an authenticated read).
- **Multiple-origin behaviour**: when ≥2 independent attacker origins (`evil.com` + `attacker.com`) are both allowed, an aggregated `multiple_origin` signal is emitted.
- **Preflight (OPTIONS) analysis** (`_probe_preflight`): an attacker-origin OPTIONS probe captures the reflected `/wrong origin` and the echoed `Access-Control-Allow-Methods`, confirmed when a wildcard/evil reflection is found.
- **Dynamic confidence** (`_confidence`): a reproducible `0–100` score derived from evidence count (independent origins, credentials present, multiple origins, cross-method reproduction, `Vary: Origin` hygiene) stored as `cors_confidence` — `0` for a restrictive policy, growing with corroboration.
- **`benchmarks/cors_benchmark.py`** — deterministic local fixture (`/reflected`, `/reflected_creds`, `/wildcard_creds`, `/null`, `/post_only` VS `/allowlist`, `/no_acao`) → `reports/cors_benchmark.json`.

### Improved
- **Evidence correlation**: each signal carries `acao`/`acac`/`vary`/`methods`/`vary_missing_origin`/`reliability`/`reproducible` plus the request/response; fingerprint adds `cors_confidence`, `cors_cross_method`, `cors_multiple_origin`, `cors_credentials`, `cors_vary`.
- **Null / wildcard / reflection detection** preserved and now credential-scaled.

### Benchmark (Phase 3.8)
- Local fixture: 5 vulnerable + 2 clean endpoints.
- **Before (v3):** `detection rate 80%` — **1 false negative** `/post_only` (an endpoint that only reflected the origin on POST was missed because only GET/`GET-request` preflight was probed).
- **After:** **detection rate 100% (5/5), 0 false positives, 0 false negatives, 2 true negatives** — `/reflected`, `/reflected_creds`, `/wildcard_creds`, `/null` and `/post_only` all detected; `/allowlist` and `/no_acao` correctly **not** flagged.

### False-positive analysis
- Broad wildcard / reflection without credentials is downgraded to a warning-level `likely` signal instead of a bulk ARG confirmed finding — an intentionally public (credential-less) resource is no longer reported as an authenticated-data read.
- A restrictive allow-list that never reflects an offending origin and a no-headers endpoint never produce a signal.

### Regression report
- `test_validation.py`: **0 errors / 0 warnings** — new §41 (CORS Configuration Detection Accuracy) covers: wildcard+credentials detection + credentials flag, origin reflection, null reflection, credential-less reflection downgrade to `likely`, POST-only (cross-method) detection, multiple-origin aggregation, preflight confirmation, restrictive-policy clean, dynamic-confidence scaling, structured per-signal metadata.
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: **REGRESSION=0** (PASS=10, WARNING=6, unchanged baseline).

Residual limitation: some endpoints legitimately use `Access-Control-Allow-Origin: *` for public (unauthenticated) assets; these are reported as `likely` warnings rather than high-severity confirmed findings.

## [4.6.0] - 2026-08-02 - CSRF Protection Detection Accuracy (SOP v4.0 Phase 3.7)

### Added
- **Token enforcement probe** (`_token_enforced`) in `scanners/csrf.py`: a token counts as enforced only when the server rejects BOTH a token-less submission AND a wrong-token one (two independent re-requests), while processing the baseline POST normally. A single static-success page can no longer produce a finding, and a missing/broken action is treated as ambiguous (never a false finding).
- **Token randomness & size** (`_token_weak` + entropy): validates the hidden token's length (≥16) and Shannon entropy; a short or low-entropy constant token is flagged as `weak_token`. A token that changes on a fresh page load is recorded as a positive `token_rotates` observation (not an issue).
- **SameSite cookie analysis** (`_samesite_profile`): per-cookie SameSite=Lax|Strict|None is inspected. A SameSite=Lax/Strict session cookie is treated as **mitigating** a missing-token form (an FP guard), while SameSite=None removes the mitigation.
- **Origin / Referer validation** (`_cross_origin_accepted`): each POST form is probed with an attacker Origin/Referer; acceptance is a `cross_origin_accepted` issue, rejection is a positive `origin_validated` observation.
- **Framework recognition** (`_detect_framework`): recognizes Django/Laravel/Rails/ASP.NET/Flask-WTF/Spring/Yii/Craft token conventions and correlates the framework with the observed token.
- **`benchmarks/csrf_benchmark.py`** — deterministic local fixture (`/no_token`, `/token_ignored`, `/weak` vs `/static`, `/samesite`, `/clean`) → `reports/csrf_benchmark.json`.

### Improved
- **Evidence correlation**: every observation (issue and positive) carries structured `raw_data` with `technique`, `form_action`, `same_site` profile, `framework`, `reliability`, `reproducible`, `samesite_mitigated`; issues are `request_response` evidence leading a FAIL, positives are `verified`.
- **FP reduction**: the same-site-mitigation guard plus the two-request enforcement probe remove the two classic CSRF FP classes (same-site missing-token and static-success-page "token ignored").

### Benchmark (Phase 3.7)
- Local fixture: 3 vulnerable + 3 clean endpoints.
- **Before (v3):** flagged any no-token form regardless of SameSite and treated a missing/broken action as a finding; no token-randomness or cross-origin gating on its own.
- **After:** **detection rate 100% (3/3), 0 false positives, 0 false negatives, 3 true negatives** — `/no_token` (`no_token` + `cross_origin_accepted`), `/token_ignored` (`token_not_enforced` + `cross_origin_accepted`) and `/weak` (`weak_token`) detected; `/static` (enforced+random), `/samesite` (SameSite mitigation) and `/clean` correctly **not** flagged.

### False-positive analysis
- A token backed by SameSite=Lax/Strict produces `no_token_mitigated_by_samesite` (positive), never `no_token`.
- Token reuse across page loads is normal server behaviour and is NOT an issue; only short/low-entropy tokens are flagged (`weak_token`).
- Cross-origin acceptance is only reported when a cross-origin submission returns an equivalent response to the same-origin baseline.

### Regression report
- `test_validation.py`: **0 errors / 0 warnings** — new §31 (CSRF Protection Detection Accuracy) covers: Django framework detection + enforced-token positive + no-issue protected form, missing-token flag, unenforced-token flag, weak-token flag, cross-origin acceptance, SameSite=Lax FP guard, SameSite cookie parsing, clean-page, structured issue metadata.
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: **REGRESSION=0** (PASS=10, WARNING=6, unchanged baseline).

Note: only the SameSite=Lax/Strict case is treated as mitigating — none cases and cookies with no SameSite at all remain reportable as missing-token.

## [4.5.0] - 2026-08-02 - Open Redirect Detection Accuracy (SOP v4.0 Phase 3.6)

### Added
- **Host-derived off-site classification** (`_is_off_site`) in `scanners/open_redirect.py`: a redirect is only an open redirect when the **effective target host** differs from the request's own host. Same-host redirects (even with a suspicious domain inside the `Location`) and same-origin relative paths are **never** classified as open redirects — closing the biggest substring-scanner FP class.
- **Ambiguous-vector fallback**: tokens that defeat a strict URL parser (`%2F`, `%252F`, credential/authority confusion) fall back to an explicit off-host substring check so detection accuracy is preserved where the parser is ambiguous.
- **Richer evidence**: every observation carries `detection_method`, `target_host` and an `off_site` flag in `raw_data` + fingerprint; cross-validation enumerates the confirmed techniques and the fingerprint records aggregated `redirect_targets`.
- **`benchmarks/open_redirect_benchmark.py`** — deterministic local fixture (`/external`, `/coded` → 302 off-site; `/internal` same-host, `/same_origin` relative → negative) → `reports/open_redirect_benchmark.json`.

### Improved
- **Technique set**: absolute, relative, protocol_relative, encoded, double_encoding, redirect_chain — each emitted as a confirmed observation only after repeated confirmation with a different payload.
- **Vector-level confirmation** preserves the baseline-threshold removes; confirm now requires repeated independent confirmation rather than a single-hit substring.

### Benchmark (Phase 3.6)
- Local fixture: 2 vulnerable + 2 clean endpoints (`/external`, `/coded` vs `/internal`, `/same_origin`).
- **Before (v3):** substring matching flagged the same-host `/internal` and relative `/same_origin` as vulnerabilities (both FPs).
- **After:** **detection rate 100% (2/2), 0 false positives, 0 false negatives, 2 true negatives** — `/external` and `/coded` confirmed; `/internal` (same-host) and `/same_origin` (relative) correctly **not** flagged.

### False-positive analysis
- Host-derived classification removes the "Location string contains the domain but resolves back to the request host" class.
- Same-origin relative redirections (`Location: /login?...`) are never open redirects to an attacker-controlled host.
- Encoded/double-encoded tokens only fall back to substring when the strict parser cannot resolve the effective host.

### Regression report
- `test_validation.py`: **0 errors / 0 warnings** — new §30 (Open Redirect Detection Accuracy) covers: external absolute detection + off-site host recording + ≥2-technique cross-validation, encoded-vector detection, same-host FP control, same-origin relative FP control, POST detection, clean page, `target_host`/`off_site` structured metadata on observations, clean no-param path.
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: **REGRESSION=0** (PASS=10, WARNING=6, unchanged baseline).

## [4.4.0] - 2026-08-02 - SSTI Detection Accuracy (SOP v4.0 Phase 3.5)

### Added
- **Per-(param, method) baseline FP-guard** in `scanners/ssti.py`: before either arithmetic value is accepted as injection proof, the scanner fetches the *benign* response for that parameter (neutral token for GET, original field value for POST; cached once) and requires **both** expected products (`49` and `72`) to be **absent** from it (`_evaluation_credible`). A page whose copy already prints "49" or "72" (counts, examples, totals) can never trigger a finding.
- **Enhanced engine fingerprinting** (`ENGINE_FINGERPRINTS` + `_match_engines`): broadened to real, distinctive markers (Jinja2 `jinja2.exceptions`/`TemplateSyntaxError`/`UndefinedError`, Twig `Twig\Error\SyntaxError`, FreeMarker `FreeMarker template error`/`TemplateModelException`, Velocity `org.apache.velocity`/`VelocityException`, Handlebars `Missing helper`, Smarty `SmartyBC`/`Smarty_Internal`, ERB `ActionView::Template`). Matching is case-insensitive (`p.lower() in low`).
- **Context-variant probes** (`ENGINE_PROBES` / `_render_text` / `_render_probes`): every confirmed evaluation additionally probes the same parameter with a second, novel render construction and scans it for fingerprints, so engine identification is corroborated beyond the base-pair.
- **Evidence correlation**: each arithmetic observation and `engine_evidence` entry now carries `fingerprint_consistent` (whether a marker matched the claimed engine) and `markers_matched`; cross-validation enumerates the confirmed engines; fingerprint output adds aggregated `engine_evidence`.
- **`benchmarks/ssti_benchmark.py`** — deterministic local fixture (generic arithmetic evaluator + FreeMarker-only fingerprint endpoint + 3 negative controls) → `reports/ssti_benchmark.json`.

### Improved
- **Baseline confirmation**: both confirmation values must be injection-introduced (not merely the primary), and checks are per-parameter rather than page-global.
- **Fingerprint consistency flag** documented in every observation (never assumes hardware; a fingerprint that doesn't match is reported as `fingerprint_consistent=False`, and only the arithmetic drives status).

### Benchmark (Phase 3.5)
- Local fixture: 2 vulnerable + 3 clean endpoints (`/math`, `/fm` vs `/fp_echo`, `/fp_baseline`, `/clean`).
- **Before (v3):** global-baseline only guarded the primary value; fingerprints were single-shot and case-sensitive; no variant correlation.
- **After:** **detection rate 100% (2/2), 0 false positives, 0 false negatives, 3 true negatives** — `/math` confirmed 5 engines; `/fm` reported **freemarker with `fingerprint_consistent`**; `/fp_echo` (reflection-only) and `/fp_baseline` (static "49"/"72") correctly **not** flagged.

### False-positive analysis
- Baseline guard closes the "page statically contains the product numbers" class for both the primary and confirm values.
- Reflection-only pages that echo raw input (with the payload verbatim, never evaluating) surface no magic numbers → no evaluation.
- Fingerprint markers are distinctive engine strings, never generic words ("template", "ruby"), and must be both present and (when the engine is claimed) consistent.

### Regression report
- `test_validation.py`: **0 errors / 0 warnings** — new §29 (SSTI Detection Accuracy) covers: generic evaluator ≥2 engines, FreeMarker-only engine + marker correlation + captured markers, POST-field detection, reflection-only echo negative, static-numbers baseline negative, clean-page, `fingerprint_consistent` flag on observations, clean no-param path.
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: **REGRESSION=0** (PASS=10, WARNING=6, unchanged baseline).

## [4.3.0] - 2026-08-02 - LFI Detection Accuracy (SOP v4.0 Phase 3.4)

### Added
- **Per-parameter baseline FP-guard** in `scanners/lfi.py`: before any file-signature match is accepted, the scanner fetches the *benign* response for that parameter (a neutral token for GET, the original field value for POST) and caches it once per `(param, method)`. A known-file marker is only reported as evidence if it is **absent** from that baseline body (`_signature_hit`). Pages that unconditionally render `root:x`, `localhost.localdomain` or an OS banner can never satisfy LFI evidence, closing the strongest residual false positive.
- **`baseline_excluded=True`** recorded in every emitted observation's `raw_data`, proving the finding was gated against the baseline (structured, auditable accuracy claim).
- **Wider markers**: `/etc/shadow` (`root:*:`, `daemon:*:`), extra passwd anchors (`/root:/bin/bash`), `/etc/hosts` (`localhost.localdomain`), `/proc/self/environ` (`DOCUMENT_ROOT=`), Apache config (`ServerToken`), Windows `boot.ini` (`[boot loader]`, `system32\ntoskrnl.exe`) and `system.ini` (`[drivers32]`), alongside the existing win.ini anchors.
- **Payload diversity**: new traversal targets (`etc/shadow`, `etc/apache2/apache2.conf`, `windows\system.ini`, `boot.ini`), more confirm paths, and broader **encoding-bypass variants** (`triple_url`, `mixed_slash`, `overlong_utf8`, `double_encoded_backslash`, plus existing `url`/`double_url`/`backslash`/`dot_overslash`) so WAF/input-filtered plain traversal is still caught.
- **`benchmarks/lfi_benchmark.py`** — deterministic local fixture (POSIX / Windows / shadow / WAF-encoded endpoints + 2 negative controls) → `reports/lfi_benchmark.json`.

### Improved
- **Markers hardened**: removed bare/anchor words (`localhost`, `Debian`, `Ubuntu`, the loose `'::1'`/whitespace token) as standalone proof — only distinctive OS-format anchors remain, and every match is additionally gated by the per-parameter baseline.
- Baseline guard applies to every technique check (traversal, disclosure, os_fingerprint, null_byte, encoding_bypass).

### Benchmark (Phase 3.4)
- Local fixture: 4 vulnerable + 2 clean endpoints (`/posix`, `/shadow`, `/win`, `/encoded` vs `/baseline`, `/clean`).
- **Before (v3):** matched any known-file marker anywhere in the response, so a page that always emitted `root:x:`/`localhost` (e.g. `/baseline`) was a **false positive**; no Apache/shadow/system.ini anchors and fewer encoding variants.
- **After:** **detection rate 100% (4/4), 0 false positives, 0 false negatives, 2 true negatives** — `/baseline` (unconditional disclosure, was an FP) and `/clean` both correctly **not** flagged.

### False-positive analysis
- Baseline guard: a marker already present in the benign response is not evidence of injection — kills the "page always renders OS banner / `root:x:`" class.
- Marker hygiene: common English words (`localhost`, `Debian`, `Ubuntu`) no longer act as standalone proof.
- Encoding bypass FD: plain traversal that a WAF strips returns nothing; encoded variants still disclose and confirm across ≥2 independent constructions.

### Regression report
- `test_validation.py`: **0 errors / 0 warnings** — new §28 (LFI Detection Accuracy) covers: POSIX traversal + disclosure, Windows config files, encoding bypass under a filtering WAF, the unconditional-marker baseline negative control, clean-page, `baseline_excluded` on every observation, and the clean no-parameter path.
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: **REGRESSION=0** (PASS=10, WARNING=6, unchanged baseline).

## [4.2.0] - 2026-08-02 - SSRF Detection Accuracy (SOP v4.0 Phase 3.3)

### Added
- **Cloud metadata endpoint detection per provider** (`CLOUD_PROVIDERS`) in `scanners/ssrf.py`: AWS EC2 IMDS, Azure Instance Metadata, Google Cloud Metadata, DigitalOcean, OpenStack/cloud-init, Alibaba Cloud ECS, and Oracle Cloud — each with provider-specific endpoints and marker vocabulary. Matching is strict (`_metadata_body_hit`): a marker only counts if it is **not** a substring of the requested URL, so an application that merely echoes the URL string back can never satisfy a metadata finding.
- **Per-provider request headers**: GCP metadata (which requires `Metadata-Flavor: Google`) and Azure IMS (which prefers `Metadata: true`) have their headers propagated on the probe request.
- **Provider classification + aggregation**: every metadata/internal observation carries `provider`; `_aggregate_providers` combines providers across independent techniques into a single fingerprint `cloud_provider` instead of claiming one from a lone signal.
- **Redirect-chain analysis** (`_walk_server_chain`): points the app at a seed and walks the *server-side* redirect chain, re-sending each emitted `Location` back through the parameter (bounded to `REDIRECT_MAX_HOPS`). A hop whose `Location` lands on an internal/cloud-metadata host yields a `redirect_chain` observation with the full ordered hop list recorded in evidence.
- **Redirect-safe probing**: SSRF probes no longer auto-follow redirects by default, so an open-proxy `Location` to an internal/off-site host never drags the scanner client off-target or into latency; the redirect technique follows each hop explicitly.
- **Evidence correlation**: `detection_method`, `provider`, `redirect_chain` and `confirm_payload` added to every emitted observation's `raw_data`; cross-validation message now names the targeted cloud provider(s).
- **`benchmarks/ssrf_benchmark.py`** — deterministic local fixture (cloud metadata / internal fetch / URL-fetch error / server-side redirect + 2 clean control pages) → `reports/ssrf_benchmark.json`.

### Improved
- Broadened payload sets: more cloud endpoints (IMDSv1 + dynamic instance identity, IAM role, Azure api-version variants, GCP project/instance/service-accounts, DigitalOcean/OpenStack/Alibaba/Oracle), more internal/private ranges (10/192.168/172.16/172.17/172.31, link-local `169.254.x`, IPv4-mapped `[::ffff:127.0.0.1]`, HTTPS localhost).
- **False-positive reduction**: `internal_access` now only counts a distinct **200** whose body size differs from baseline by `>300`, and generic error bodies (`404 Not Found`, `Forbidden`, `Runtime error`, `Service unavailable`, …) are excluded — a generic app 4xx/5xx page can no longer be read as internal reachability.
- **Metadata echo guard**: requested URL is stripped from classification markers, closing the classic "verbose error echoes the URL" false positive.
- Stack size: requires ≥2 independently requested metadata paths (same provider) before an observation is emitted.

### Benchmark (Phase 3.3)
- Local deterministic fixture: 4 vulnerable + 2 clean endpoints (`/meta`, `/icols`, `/err`, `/redir` vs `/echo`, `/clean404`).
- **Before (v3):** cloud detection keyed on generic `169.254.169.254` `meta-data` words (no provider attribution, echoed-URL FP), no redirect-chain walk, internal detection accepted any non-(200/3xx/404) status or `>500` size delta (generic error pages were false positives).
- **After:** **detection rate 100% (4/4), 0 false positives, 0 false negatives, 2 true negatives**; `/meta` reported **AWS + Azure + GCP** provider classification; `/redir` yielded a server-side redirect-chain observation; `/echo` and `/clean404` correctly **not** flagged.
- External targets (Juice Shop / DVWA / bWAPP / a metadata-fetch lab) run via `python -m benchmarks.ssrf_benchmark --targets <url>...`.

### False-positive analysis
- Echo guard: markers are required to be absent from the requested URL, so reflecting the request URL (verbose error) can never satisfy metadata.
- Internal: restricted to distinct 200 minus generic-body exclusion — generic 404/403/500/503 pages correctly do not raise `internal_access`.
- Redirect: only a server-emitted `Location` to an internal/cloud target triggers; probing hints do not themselves follow external redirects.

### Regression report
- `test_validation.py`: **0 errors / 0 warnings** — new §27 (SSRF Detection Accuracy) covers: AWS/Azure/GCP provider classification, header-based GCP detection, metadata does **not** fire on a URL echo page, generic 404 page not flagged as internal access, server-side redirect-chain detection + recorded hops, multiple-technique cross-validation + provider aggregation, and the clean no-parameter path.
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: **REGRESSION=0** (PASS=10, WARNING=6, unchanged baseline).

## [4.1.0] - 2026-08-02 - XSS Detection Upgrade (SOP v4.0 Phase 3.2)

### Added
- **Context-aware payload selection** (`self.context_payloads`) in `scanners/xss.py`: each reflection context (html / attribute / javascript) now carries a named, production-shaped payload set — `<script>alert</script>`, `<img onerror>`, `<svg onload>`, `<body onload>` for HTML; double/single-quote breakout, `autofocus` event and unquoted event for attributes; `</script><script>`, `';alert(1);//`, `template`-literal `${alert(1)}` for JavaScript. Payloads are worst-first so the most definitive case is confirmed first.
- **Concrete sink classification** (`self.sink_rules` + `_classify_sink()`): every emitted observation now reports exactly *where* the payload executed — `script_tag`, `img_event`, `svg_event`, `body_event`, `quote_breakout`, `unquoted_event`, `script_breakout`, `js_string_breakout`, `template_breakout`.
- **Stored-XSS persistence probe** (`_check_stored`): after a confirmed reflected context, one POST persists the payload and a subsequent *payload-free* GET is read back; a surviving marker yields an independent `stored_persistence` support evidence. Bounded to one POST + one GET, never a standalone finding.
- **DOM-source indicative detection** (`_check_dom`): a reflected parameter whose value also flows into a dangerous DOM sink (`.innerHTML=`, `.outerHTML=`, `document.write(`, `.insertAdjacentHTML`, `eval(`, `.setAttribute`, `.textContent=`, `.href=`, `.location=`) inside the same inline `<script>` block emits a conservative `dom_source` support signal. **No rendering engine** is used (scope guard): it is explicitly an *indicative* signal, never a standalone finding.
- **Escape-aware false-positive guard** (`_strip_escaped`): entity-escaped tags (`&lt;img ... &gt;`, `&quot;...&quot;`) are stripped before marker/context matching, so server-side HTML encoding can no longer be mistaken for executable reflection even though `src=`, `onerror=` and `alert(1)` survive encoding literally.
- **`benchmarks/xss_benchmark.py`** — self-contained, deterministic local-fixture benchmark (True Positive / False Positive / False Negative / True Negative / detection rate / average scan time) plus an external-target hook. Output: `reports/xss_benchmark.json`.

### Improved
- Richer family payloads and context regexes: SVG event handler, single/double-quote breakout, `autofocus`/unquoted injection, JS template-literal breakout.
- `_emit_observation` attaches `sink`, `matched_rule`, `verification_pass`, `reproducibility`, `verify_payload` to every evidence `raw_data`; `_emit_support` now emits `stored_persistence` and `dom_source` (uses `likely`; `dom_source` rests at `possible`/`indicative`).
- Confidence remains fully dynamic via the engine — cross-context agreement (e.g. HTML + attribute + JavaScript on the same parameter) raises confidence and emits `cross_validation`.

### Benchmark (Phase 3.2)
- Local deterministic fixture: 3 vulnerable + 2 clean endpoints (raw-HTML reflection, attribute reflection, DOM-sink reflection, static page, server-escaped page).
- **Before (legacy v3):** attribute/sink knowledge was coarse (per-family only, no sink), no stored or DOM-source signals; an escaped page that retains literal `onerror=`/`src=` text could be flagged.
- **After:** **detection rate 100% (3/3), 0 false positives, 0 false negatives, 2 true negatives**; `.html` and `.attr` confirmed with multiple contexts + sink classification; `/dom` produced an extra `dom_source` indicative support signal; `/escaped` correctly **not** flagged (escape guard).
- External XSS targets (OWASP Juice Shop, DVWA, bWAPP, PortSwigger Web Academy XSS labs) are benchmarkable via `python -m benchmarks.xss_benchmark --targets <url>...`.

### False-positive analysis
- The main Phase 3.2 FP class (escaped output = `&lt;script&gt;`/`&quot;`) is closed by `_strip_escaped`: entity-encoded markers are removed before matching, so a properly escaped page yields no signal. Benchmark `/escaped` verified 0 FP.
- DOM-source is deliberately `possible`/`indicative` (no rendering engine) so a static sink keyword cannot alone raise a finding; it only corroborates a confirmed reflected context.
- Stored-persistence is only probed **after** a confirmed reflected core context, bounding the extra POST/GET and preventing stored signal from firing on an unreflected page.

### Regression report
- `test_validation.py`: **0 errors / 0 warnings** — new §26 (XSS Detection upgrade) covers: script-tag HTML context with sink classification, attribute quote-breakout context, DOM-source indicative support signal, stored-persistence probe (POST → payload-free GET), context-aware payload sets (HTML/attribute/JS + SVG + template literal), engine dynamic confidence across multiple contexts, and the clean no-parameter path.
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: **REGRESSION=0** (PASS=10, WARNING=6, unchanged baseline).

## [4.0.0] - 2026-08-02 - SQL Injection Upgrade (SOP v4.0 Phase 3.1)

### Added
- **Two new independent injection techniques** in `scanners/sqli.py`, in addition to the existing error/boolean/time-based:
  - **UNION-based** (`union_based`) — locates the injectable column count via an `ORDER BY` oracle, then proves injection with a `UNION SELECT` that reflects a unique marker; a second, reordered marker-shaped UNION confirms it. Non-regex corroboration (never relies on an error signature alone).
  - **Stacked queries** (`stacked_queries`) — a gated technique that only arms once another pass has fingerprinted a stacking-capable DBMS (MSSQL/PostgreSQL/MySQL), then confirms a stacked-statement delay across two independent payloads. It never fires as the sole signal, bounding false positives.
- **DBMS fingerprinting** (`_db_fingerprint()`): every confirmed observation contributes a database candidate with technique provenance. The scanner aggregates a per-DB confidence (`database_fingerprint`) so a database is never claimed on a single signal; `fingerprint['database']` stays the backward-compatible sorted-list.
- **Structured evidence** upgrade on every emitted observation: `detection_method`, `independence`, `reproducibility` (number of confirming passes), `confirm_payload`, `database`, `database_confidence` and technique-listed timing/comparison dicts — all in the evidence `raw_data` alongside the existing request/response snapshot.
- **`benchmarks/sqli_benchmark.py`** — self-contained, deterministic local-fixture benchmark measuring **true positives / false positives / false negatives / true negatives / detection rate / average scan time**, plus an external-target hook (`--targets`) for Juice Shop / DVWA / Mutillidae / WebGoat / bWAPP / PortSwigger Web Academy when those applications are available. Output: `reports/sqli_benchmark.json`.

### Improved
- Expanded `error_payloads` and DBMS signature rules (Oracle, MSSQL, PostgreSQL, SQLite additions), async per-engine time payloads for Oracle.
- Boolean detection now carries a behavioural (non-regex) `detection_method` and reports reasoning for the differential.
- Confidence is fully dynamic — never static. The v3 engine derives it from the number of evidences, independent observations, verification passes and cross-validation, so multi-technique agreement (e.g. error + time + stacked) visibly raises it and emits a `cross_validation` evidence item.

### Benchmark (Phase 3.1)
- Local deterministic fixture: 4 vulnerable + 2 clean endpoints.
- **Before (legacy v3):** detection rate ~75% (UNION/stacked endpoints were false negatives), clean-control FP absent on fixed pages.
- **After:** **detection rate 100% (4/4), 0 false positives, 0 false negatives, 2 true negatives**; all techniques identified (`union_based`, `stacked_queries`, `error_based`, `time_based`, `boolean_based`).
- External targets (OWASP Juice Shop, DVWA, Mutillidae, WebGoat, bWAPP, PortSwigger Academy labs) are benchmarkable via `python -m benchmarks.sqli_benchmark --targets <url>...` — they must be reachable in the test environment.

### False-positive analysis
- The new UNION technique reflects a unique marker in two, reordered columns before reporting — a reflected-marker end cut eliminates the FP class that a single reflection check would allow on `text` endpoints that reflect input verbatim.
- Stacked-query firing is gated on a prior MS SQL/PostgreSQL/MySQL fingerprint, so a lone stacking-style delay probe without a DB-based corroborating technique cannot alone raise a FAIL.
- Boolean differentiation requires **two independent** true/false constructions to agree; a bare 1-char content wiggle on an input-echo page below the length/similarity thresholds is not counted.
- Residual/known limitations for Phase 3.1: (a) a pathological page that reflects the injected `OR`/`AND` keywords *and* returns different bodies could still yield a boolean signal (mitigated by the similarity threshold ≥ 0.8); (b) time-based false negatives occur when a WAF/proxy caps the request timeout below the ~6 s delay floor; (c) UNION detection cannot fire on targets that return generic 500s for an out-of-range `ORDER BY` without distinct content — its column oracle requires a detectable change.

### Regression report
- `test_validation.py`: **0 errors / 0 warnings** — new §25 (SQL Injection upgrade) covers UNION oracle+reflection, non-regex corroboration, error-based MySQL fingerprint + detect method/reliability, boolean dual-pair, stacked gating, provenance-aware DB fingerprint, structured evidence, dynamic confidence and the clean no-parameter path.
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: **REGRESSION=0** (PASS=10, WARNING=6, unchanged baseline).

## [3.10.0] - 2026-08-02 - Advanced Smart Crawling (SOP v4.0 Phase 2)

### Added
- **New dedicated crawling subsystem** (`core/crawler/`) replacing the legacy single-module crawler. The public API stays fully backward compatible — `from core.crawler import Crawler` still exposes `crawl()`, `extract_post_forms()`, `visited`, `pages`, `diag` and the 49 `SKIP_EXTENSIONS`.
  - `crawler.py` — bounded breadth-first orchestrator over an explicit queue (no recursion); honours pages/depth/request/duration budgets and aborts gracefully.
  - `queue.py` — `CrawlQueue` with depth limits + enqueued-set de-dup (infinite-precrawl prevention).
  - `scope_manager.py` — `ScopeManager`: `domain | subdomain | path | all` + `include_subdomains` + include/exclude regex patterns.
  - `url_normalizer.py` — `URLNormalizer`: strips fragments, default ports, duplicate slashes, dot-segments, tracking params (utm_*/fbclid/gclid/ref/…); lower-cases hosts → canonical identity.
  - `robots_parser.py` — `RobotsParser`: download/parse robots.txt (allow/disallow/crawl-delay/sitemaps). Disallowed paths only honoured opt-in (`respect_robots`), never silently.
  - `sitemap_parser.py` — `SitemapParser`: sitemap.xml / sitemap-index / gzip parsing merged into the crawl queue.
  - `link_discovery.py` — anchors, nav menus, form actions, canonical links, meta-refresh targets + static JS URL extraction (no rendering).
  - `page_classifier.py` — Login/Admin/API/Dashboard/User Profile/Search/Product/Documentation/Static/Home categorization.
  - `deduplicator.py` — URL + redirect + content-hash de-duplication.
  - `crawl_statistics.py` — counters exposed as legacy-compatible `diag` plus Phase 2 keys.
  - `forms_helper.py` — shared POST-form extraction (preserves legacy behaviour).
- **`core/config.py`**: `ScanConfig` gains `max_depth`, `max_crawl_requests`, `max_crawl_duration`, `crawl_strategy`, `crawl_scope`, `include_subdomains`, `crawl_include_patterns`, `crawl_exclude_patterns`, `respect_robots`, `parse_sitemap`.
- **CLI** (`sea.py`): `--max-pages`, `--max-depth`, `--scope {domain,subdomain,path,all}`, `--include-subdomains`, `--respect-robots`, `--parse-sitemap`, `--no-sitemap`.
- **GUI** (`gui/pages/scanner_page.py`): new "Crawl Settings" card (Max depth, Max duration, Scope, Include subdomains, Respect robots.txt, Parse sitemap.xml) → `build_crawl_config()` → `start_scan(crawl=...)`.
- **Reporting** (`core/reporter.py` + `templates/report.html.j2`): Attack Surface Summary gains a "Crawl Discovery (Phase 2)" grid (URLs discovered, Login/Admin/API pages, Forms, JS files, Sitemap entries, Robots entries, Duplicates).
- **`main.py` / GUI `ScanWorker`**: build the `Crawler` with the new options and pipe Phase 2 metrics into `ScanResult` (`crawl_duplicates/redirects/failed/duration/sitemap/robots`, `attack_surface`, `crawl_classifications`).

### Changed
- Legacy `core/crawler.py` single module removed; replaced by the `core/crawler/` package (import-identical).
- `<link rel=canonical>` and meta-refresh targets are now discovered and enqueued; sitemap/robots are parsed for coverage.

### Validation
- `python test_validation.py`: 0 errors / 0 warnings — new §24 "Advanced Smart Crawling" covers URL normalization, scope management, robots/sitemap parsing, queue depth + de-dup (infinite-precrawl), crawler dedup identity, page classification, stats `diag`, form extraction and CLI flags.
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: `REGRESSION=0` (PASS=10, WARNING=6 — unchanged golden baseline).
- End-to-end local-server crawl verified BFS discovery, sitemap merging, robots parsing, duplicate suppression and attack-surface classification.

## [3.9.0] - 2026-08-02 - Optional Authentication Support (SOP v4.0 Phase 1)

### Added
- **New `core/auth/` provider package** — authentication is optional and anonymous scanning stays the default, unchanged. Scanners contain no authentication logic; they receive the configured session transparently.
  - `base.py`: `AuthSpec` (single input contract: `type`, `cookie_file`, `cookie_string`, `token_file`, `token`, `headers`, `validate`) + `BaseProvider`.
  - `cookie_provider.py` (Netscape ≥7 tab-separated + `name=value` lines), `bearer_provider.py`, `jwt_provider.py` (first non-empty non-comment file line or inline value), `header_provider.py` (repeatable `"Name: Value"`).
  - `session_validator.py`: `SessionValidationResult` (`valid`/`applicable`/`status_code`/`classification`/`redirected_to_login`/`reason`/`message`) + `SessionValidator` — probes with a **fresh** `requests.Session()` (never mutates the tracked crawl session) and rejects on 401/403, redirect-to-login, or a login-page body.
  - `authentication_manager.py`: `AuthenticationManager` facade — `build` returns `None` for anonymous/no-auth, raises `ValueError` on unsupported type or empty credentials; `apply_to`/`activate`/`validate`/`mark_invalid` (token methods → `token_invalid`, cookies → `session_expired`).
  - `__init__.py` re-exports the existing `core.auth_manager` API (AuthSession/AuthDetector/AuthState/classify_auth_response/is_login_path) as a facade.
- **`sea.py` automation CLI**: `sea scan <target>` anonymous by default; `--cookies FILE` / `--bearer FILE` / `--jwt FILE` / `--header "Name: Value"` (exactly one method, exit code 2 on conflict); `--no-validate-session`, `--mode quick|standard|deep`, `--threads`, `--timeout`, `--no-auth-detection`, report-format flags (`--json`/`--markdown`/`--csv`/`--txt`, `--no-html`), `--report-dir`. Forces UTF-8 stdio so Rich's unicode banner no longer crashes when stdout is piped on a cp1252 Windows console.
- **`main.py` non-interactive entry**: `run_scan(target, *, auth_spec=None, report_formats=("html","json"), report_dir="reports")` — login detection is informational only (`_show_login_detected_hint`, never forces auth); session validation runs only when auth is enabled; on validation failure the scan continues anonymously with a clear warning. `generate_reports_formats(formats, report_dir)`.
- **GUI Authentication card** (`gui/pages/scanner_page.py`): "Enable authenticated scanning" checkbox reveals/hides the type radios (Cookies/Bearer/JWT/Custom Headers) and per-type fields plus a "Validate session before scanning" checkbox; `build_auth_spec()` → `ScanController.start_scan(auth_spec=...)` → `ScanWorker` (build/attach/validate with clear logs, re-crawl to count protected pages, informational login-detection message). Summary shows "Auth: <mode> (session valid/invalid)".

### Changed
- `core/auth_manager.py`: `AUTH_METHOD_LABELS['public']` is now `'Anonymous'` (was `'Public Scan'`); added `'jwt': 'JWT Token'` and `'headers': 'Custom Headers'`; `AuthSession` gains `set_jwt_token()` and `configure_headers()`.
- `core/finding.py`: `evaluate_auth_state()` treats `jwt`/`headers` methods like `bearer` for token-invalid detection; `_auth_stats()` now reports `authenticated`, `mode`, `session_valid`, `session_checked`.
- `core/config.py`: `ScanConfig` gains `auth_enabled`, `auth_type`, `auth_cookie_file`, `auth_cookie_string`, `auth_token_file`, `auth_token`, `auth_headers`, `auth_validate_session`.
- `core/reporter.py`: Authentication section now shows Mode, Authenticated, Session Valid, and Protected Pages Scanned (in addition to detection/coverage); default method label falls back to "Anonymous".
- Docs: `PROJECT_STATE.md`, `project_docs/CHANGELOG.md`, `SOP.md`, `docs/ENGINE_ARCHITECTURE_V3.md`.

### Validation
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: `REGRESSION=0` (PASS=10, WARNING=6 — explained v3 verification-band shifts, snapshot-level gate zero).
- `python test_validation.py`: 0 errors / 0 warnings — new §23 covers the `core.auth` package (providers, `AuthSpec.enabled`, `AuthenticationManager` build/apply/mark_invalid, `SessionValidator` against patched `requests.Session`: 401 / redirect-to-login / login-body / valid / anonymous-skip) and `sea` CLI parsing (anonymous→None, conflict exit 2, `--jwt`/`--header`/`--no-validate-session`, deep preset).
- End-to-end `sea` scans against a local server (valid bearer → `authenticated`, `session_valid=true`; invalid bearer → `state=token_invalid`, `session_valid=false`, continues anonymously; anonymous → no auth section, default UX unchanged). GUI `ScanWorker` auth flow verified offscreen (anonymous + valid + invalid + login-detection hint).

## [3.8.0] - 2026-08-02 - Assessment Orchestrator Integration (A9)

### Changed
- **Single assessment lifecycle per scan (A9 landed).** Every production orchestrator now calls
  `scan_result.assess()` exactly once and reads the one immutable `Assessment`:
  - `core/pipeline.py`: `run_assessment_pipeline` is **idempotent** — it builds the full
    lifecycle (correlation boosts → Risk Engine → Coverage Engine → Assessment Engine →
    Executive Summary) and stores the result on `scan_result.assessment`; a second call returns
    the existing `Assessment` (correlation is never applied twice).
  - `core/finding.py`: `ScanResult` gains an `assessment` attribute and an `assess(**kwargs)`
    gateway. Legacy `get_statistics` / `get_coverage` / `get_execution_states` /
    `get_overall_severity` / `calculate_dynamic_risk_score` / `calculate_risk_breakdown` /
    `run_correlation` now **delegate to the stored Assessment** (inline engine fallback only for
    un-assessed results used by the test harness). `run_correlation()` returns `[]` once assessed.
  - `main.py` (`CLI`): `run()` calls `self.scan_result.assess()` before summary/report generation;
    `run_scan_on_all_pages()` no longer calls `run_correlation()`.
  - `gui/services/scan_worker.py`: replaces `run_correlation()` with `scan_result.assess()`;
    `_build_summary` reads `assessment.assessment_confidence`.
  - `gui/main_window.py` + `gui/pages/history_page.py`: history persists and prefers the
    Assessment-derived `overall_tier`.
  - `backend/app/scan_runner.py`: the OAIST confirmation write is now an **engine hook** —
    matching interactions append `EvidenceBuilder().exploited(...)` evidence and the pipeline
    derives verification/confidence/severity (no direct `verification_status`/`confidence=100`
    overrides). The final phase reads `assessment.statistics` (risk/tier/correlations_found)
    instead of manual `CorrelationEngine.correlate()` + `get_statistics()`.
  - `core/reporter.py` / `core/pdf_reporter.py`: new `_stats(scan_result)` helper reads the
    stored Assessment first (Assessment-first, legacy fallback only for un-assessed results).
- **Docs updated**: `docs/ENGINE_ARCHITECTURE_V3.md` (§7 data flow, §8 backward-compat, Phase A9
  table → completed), `docs/TECHNICAL_DEBT.md` (OAIST §3.4 resolved; §4 table; §5 A9 → completed).

### Validation
- `python -m tests.engine_tests`: 0 errors / 0 warnings.
- `python -m tests.regression_runner`: `REGRESSION=0` (PASS=10, WARNING=6 — all diffs explained
  v3 verification-band-shift differences, snapshot-level gate zero).
- `python test_validation.py`: 0 errors / 0 warnings.
- py_compile clean on all 9 modified files; GUI/backend modules import cleanly.
- Delegation parity: after `assess()`, `get_statistics()` == `assessment.statistics` (exact dict),
  verdict/risk/coverage/execution-states match the pipeline, and `run_assessment_pipeline` is
  idempotent — verified on clean_site / sqli_detected / mixed_corpus / scan_incomplete / scan_error.
- Remaining validation item: `python -m tests.live_scan_runner <target>` live replay (requires a
  live target or a raw `--session` fixture).

## [3.7.0] - 2026-08-01 - Engine v3 Migration Cleanup & Architecture Freeze (A8.9)

### Changed
- **Archived the v2 decision logic** in `tests/v2_reference.py` (test-only; production never imports it): `v2_decide`, `V2DecisionEngine`, `v2_apply_evidence_assessment`, `v2_compute_execution_state`, plus the archived helpers (`v2_highest_evidence_level`, `v2_build_confidence_explanation`, `v2_update_verification_status`, `v2_collect_matched_rules`). `EVIDENCE_LEVEL_LABELS` re-defined locally.
- **`core/decision_engine.py`** reduced to the standards metadata provider (STANDARDS / RECOMMENDATIONS / CVSS_DESCRIPTIONS / PASS_* / FAIL_* / WARNING_* / SEVERITY_BY_MODULE) + `RiskCalculator` (kept for `ScanResult.get_statistics()` until A9/A10). `decide()` and all `_*` helpers removed.
- **`core/finding.py`**: `add_evidence()` is now a plain append (no v2 auto-assessment side effect); removed `_update_confidence_from_evidence`, `_update_verification_status`, `_highest_evidence_level`, `_build_confidence_explanation`, `compute_execution_state`, `collect_matched_rules`, `EVIDENCE_LEVEL_LABELS`. `verification_label` / `execution_label` are read-only properties (execution falls back to `CoverageEngine.classify_execution_state` when unset). `get_execution_states()` reads stored state with a Coverage Engine fallback.
- **`core/severity_engine.py` / `core/pipeline.py`**: `respect_existing` removed — the module map is the single authority for severity; preset severities are ignored.
- **`scanners/base.py`**: removed `use_engine_pipeline`, the legacy `decide()` branch in `run()`, `_decision_engine`/`_verification_engine`/`_response_analyzer`, `create_safe_finding`/`create_vulnerable_finding`, `verify_multi_pass`, `add_verification_evidence`, `add_payload_evidence`, `capture_response_analysis`. `run()` always runs the engine pipeline.
- **19 scanner files**: removed the `use_engine_pipeline = True` line (the flag no longer exists).
- **Test harnesses**: `tests/engine_paths.py` rewritten (`run_v2`/`run_v2_on` use `tests.v2_reference.v2_decide`; `run_v3`/`run_v3_on` use `run_assessment_pipeline`); `tests/engine_tests.py` reworked (single-writer severity assertions, section 7 architecture guard, ConfidenceEngine↔v2 parity now via `v2_apply_evidence_assessment`); `tests/diffing.py` severity message updated; `test_validation.py` legacy call sites routed through `tests.v2_reference` / the pipeline.
- **Validation**: `python -m tests.engine_tests` green; `python -m tests.regression_runner` REGRESSION=0; `python test_validation.py` 0 errors / 0 warnings.

## [3.6.0] - 2026-08-01 - Engine v3 Migration Final Batch (LFI / SSRF / Open Redirect / SSTI) — **19/19 complete**

### Changed
- **Migrated scanners to evidence-only (Final Batch, 19/19)**: `scanners/lfi.py` (LFI Detection), `scanners/ssrf.py` (SSRF Detection), `scanners/open_redirect.py` (Open Redirect), and `scanners/ssti.py` (SSTI Detection) rewritten to set `use_engine_pipeline = True` and emit raw evidence only. Status, severity, confidence, verification, and execution state are derived exclusively by the v3 engine pipeline. **No scanners remain on the legacy `decide()` path** — the migration is complete.
- **`tests/corpus.py`**: the legacy `_finding` helper was **deleted**; `ssti_detected`, `lfi_ssrf`, `cors_open_redirect`, `clean_site`, `scan_incomplete`, and `scan_error` converted to `_raw_finding` mirroring the migrated scanners' real multi-signal output; golden baselines regenerated.
- **`tests/engine_tests.py`**: migrated-set assertion (19 modules), 0-on-legacy count, runtime contract tests for the 4 new scanners (the AST evidence-only guard already covers the new sources).
- **`test_validation.py`**: SSTI scanner checks updated for the evidence-only contract (UNKNOWN/NONE + no-params `verified` evidence instead of `SKIPPED`); SSRF/Open Redirect added to the BaseScanner-method inheritance loop.

### Improved Detection Accuracy (repeated confirmation, no single-observation findings)
- **LFI Detection**: multi-technique `lfi_signals[]` + `files_disclosed` fingerprint. `traversal` requires a known-file content signature (root:x: etc.) to reproduce on two distinct paths; `disclosure` requires ≥2 distinct sensitive-file markers on independent payloads; `os_fingerprint`, `null_byte` (`%00` discloses a file the plain path does not), `encoding_bypass` (URL / double-URL / backslash / dot-overslash, reconfirmed with a second variant), `error_signature`. Adaptive depth 3–8. **2+ techniques** add `cross_validation` (verified) evidence.
- **SSRF Detection**: multi-technique `ssrf_signals[]` fingerprint. `metadata` (169.254.169.254 / Google computeMetadata markers, reproduced on a second endpoint), `internal_access` (baseline-differential response to a private address, reproduced on a second address), `error_signature` (URL-fetch error strings reproduced), `redirect`, and `oast` (OAIST out-of-band when an OAST manager is configured — never a hard failure without one). **2+ techniques** add `cross_validation` (verified) evidence.
- **Open Redirect**: multi-technique `open_redirect_signals[]` fingerprint. `absolute`, `relative`, `protocol_relative`, `encoded`, `double_encoding` vectors, each confirmed only when **two distinct payloads** yield an off-host `Location` (decoding normalization in `_decoded_location`). **2+ techniques** add `cross_validation` (verified) evidence.
- **SSTI Detection**: multi-engine evidence-only `ssti_signals[]` + `engines` fingerprint. `arithmetic_evaluation` per engine (jinja2/twig/freemarker/velocity/handlebars/smarty/erb) confirmed only when **two distinct math expressions** evaluate to the expected results (`{{7*7}}`→49 AND `{{8*9}}`→72), ruling out numbers already present in the page; `{{ expr }}` syntax families deduped so one evaluation never claims multiple engines. **2+ engines** add `cross_validation` (verified) evidence.

### Quality
- `test_validation.py`: 0 errors / 0 warnings.
- Engine unit tests: 0 errors / 0 warnings.
- Golden regression: `REGRESSION=0` (PASS=10, WARNING=6 - all diffs explained band shifts).
- Live scan runner + session save/replay on the Final Batch scanners' raw output: `PASS`, exact engine parity with no diffs.

## [3.5.0] - 2026-08-01 - Engine v3 Migration Batch 4 Part 2 (SQL Injection / XSS Detection)

### Changed
- **Migrated scanners to evidence-only (Batch 4 Part 2, 15/19)**: `scanners/sqli.py` (SQL Injection) and `scanners/xss.py` (XSS Detection) rewritten to set `use_engine_pipeline = True` and emit raw evidence only. Status, severity, confidence, verification, and execution state are derived exclusively by the v3 engine pipeline. The remaining 4 scanners (LFI, SSRF, Open Redirect, SSTI) stay on the legacy `decide()` path until the final batch.
- **`tests/corpus.py`**: `sqli_detected`, `xss_detected`, `mixed_corpus`, `scan_incomplete`, and `scan_error` scenarios converted to raw findings mirroring the rewritten scanners' real multi-signal output (`request_response` observations with `verification_pass = 2`, `cross_validation` evidence); golden baselines regenerated.
- **`tests/engine_tests.py`**: migrated-set assertion (15 modules), 4-on-legacy count, runtime contract tests for SQLi / XSS (the AST evidence-only guard already covers the new sources).

### Improved Detection Accuracy (repeated confirmation, no single-payload findings)
- **SQL Injection**: multi-technique `sqli_signals[]` + `database` fingerprint. `error_based` requires a per-DB signature (mysql/postgresql/mssql/oracle/sqlite) on the primary payload **reproduced with a second distinct payload**; `boolean_based` requires true/false responses differing by ≥40 bytes / status / `<0.8` Jaccard similarity **reconfirmed with the independent `'/**/OR/**/1=1-- -` comment-injection pair**; `time_based` requires a delay ≥ `max(baseline+4,6)s` (3-sample median baseline) **reproduced on retry** with variance recorded. Every observation is structured `request_response` evidence carrying technique/matched_rule/database/reliability/reproducible/confirm_payload/timing/comparison. **2+ techniques** add `cross_validation` (verified) evidence — multi-signal agreement is the only path to `verified`; a single technique caps at `likely`/80.
- **XSS Detection**: multi-context `xss_signals[]` + `reflected_params` fingerprint. `html` / `attribute` / `javascript` families, each tested per parameter with a primary payload **reconfirmed with a second distinct payload + an independent context regex** (no single-regex confirmation). Context patterns are executable-location-precise (`alert(` must sit inside the same tag/script), so pages that only echo HTML-escaped input (`&lt;script&gt;`) never match; attribute context requires a literal quote breakout. **2+ contexts** add `cross_validation` (verified) evidence; encoded-probe decoding is `likely` support evidence emitted only alongside a confirmed core context (never a standalone finding).

### Quality
- `test_validation.py`: 0 errors / 0 warnings.
- Engine unit tests: 0 errors / 0 warnings.
- Golden regression: `REGRESSION=0` (PASS=9, WARNING=7 - all diffs explained; `sqli_detected` and `xss_detected` moved WARNING→PASS to exact parity).
- Live scan + session save/replay on `https://example.com`: `PASS`, exact engine parity with no diffs.

## [3.4.0] - 2026-08-01 - Engine v3 Migration Batch 4 Part 1 (evidence-only scanners)

### Changed
- **Migrated scanners to evidence-only (Batch 4 Part 1, 13/19)**: `scanners/cors.py` (CORS Configuration), `scanners/csrf.py` (CSRF Protection), `scanners/host_header.py` (Host Header Injection) now set `use_engine_pipeline = True` and emit raw evidence only. Status, severity, confidence, verification, and execution state are derived exclusively by the v3 engine pipeline. The remaining 6 scanners (SQLi, XSS, LFI, SSRF, Open Redirect, SSTI) stay on the legacy `decide()` path.
- **`tests/corpus.py`**: `cors_misconfig`, `cors_open_redirect`, `host_header_csrf`, `mixed_corpus`, and `clean_site` scenarios converted to raw findings mirroring the migrated scanners' multi-signal output; golden baselines regenerated.
- **`tests/engine_tests.py`**: migrated-set assertion (13 modules), 6-on-legacy count, runtime contract tests for CORS / CSRF / Host Header (the AST evidence-only guard already covers the new sources).

### Improved Evidence Normalization
- **CORS Configuration**: multi-signal `cors_signals` fingerprint — `wildcard_credentials`, `wildcard_origin`, `null_origin`, `origin_reflection` (confirmed/likely) + `credentials_with_acao` (support) + an OPTIONS `preflight_confirmed` probe. Support signals emit only when a core issue exists; `Vary: Origin` absence is carried as metadata (not an evidence item) so multi-signal agreement raises confidence instead of being capped by a `possible` item. Clean policy -> `verified` restrictive-policy evidence. `tests_performed = 5`.
- **CSRF Protection**: multi-observation per POST form — `no_token`, `cross_origin_accepted` (Origin/Referer gating probe), `token_not_enforced` (behavioural token-removal test), `token_enforced` (verified positive). No POST forms keeps the `verified` + `NOT_APPLICABLE`-preserving pattern; observations sorted issues-first.
- **Host Header Injection**: multi-observation per test host — `body_reflection`, `redirect_location`, `generated_url` (confirmed) + `cache_poisoning_risk` (likely, gated: response diff + missing Vary Host/Origin + the injected host value must actually appear in the differing response, so a bare vhost content change on a clean site is not flagged).

### Quality
- `test_validation.py`: 0 errors / 0 warnings.
- Engine unit tests: 0 errors / 0 warnings.
- Golden regression: `REGRESSION=0` (PASS=7, WARNING=9 - all diffs explained).
- Live scan + session replay on `https://example.com`: `PASS`, no unexplained v2/v3 diffs.

## [3.3.0] - 2026-08-01 - Engine v3 Migration Batch 3 (evidence-only scanners)

### Changed
- **Migrated scanners to evidence-only (Batch 3 of 10/19)**: `scanners/tech_detect.py` (Technology Detection), `scanners/security_txt.py` (Security.txt), `scanners/source_leaks.py` (Source Code Leaks), `scanners/cookies.py` (Cookies Security) now set `use_engine_pipeline = True` and emit raw evidence only. Status, severity, confidence, verification, and execution state are derived exclusively by the v3 engine pipeline.
- **`core/response_analyzer.py`**: `CookieAnalysis` now carries per-attribute cookie data (`prefix` added, pre-classified `issues` list removed); new `detect_technology_fingerprints()` returns structured `{technology, source, signal, detail}` records and `_detect_technologies` delegates to it.
- **`tests/corpus.py`**: clean_site, xss_detected, sqli_detected, tls_strong, cms_wordpress, ports_http_sensitive scenarios converted to raw findings mirroring the migrated scanners' output; golden baselines regenerated.
- **`tests/engine_tests.py`**: migrated-set assertion (10 modules), 9-on-legacy count, runtime contract tests for Technology Detection / Security.txt / Source Code Leaks / Cookies.

### Improved Evidence Normalization
- **Cookies Security**: one evidence item per attribute (Secure/HttpOnly/SameSite/Prefix/Expiration/Domain/Path); attribute present -> `verified`, absent -> `likely`. Issue items sorted first so the v3 positive-observation rule never reclassifies a WARNING. No-cookies case keeps `tests_performed = 0` + a `verified` evidence item (preserves NOT_APPLICABLE execution state).
- **Security.txt**: fingerprint `security_txt_state` distinguishes `missing` / `valid` / `accessible` / `invalid` (empty body) / `malformed` (no `Key: value` directives); probes `/.well-known/security.txt` then `/security.txt` (2 tests).
- **Source Code Leaks**: 6 categories / 21 patterns; API Keys + Configuration Disclosure = `confirmed`-level evidence, Debug Information/Emails/Comments/Source Maps = `likely`-level; fingerprint `leak_categories` + `detection_methods`.
- **Technology Detection**: one `verified` evidence per technology with `raw_data` provenance; `tests_performed = 16`; no-detection emits a `verified` evidence item.

### Quality
- `test_validation.py`: 0 errors / 0 warnings.
- Engine unit tests: 0 errors / 0 warnings.
- Golden regression: `REGRESSION=0` (PASS=7, WARNING=9 - all diffs explained).
- Live scan + session replay on `https://example.com`: `WARNING` / `PASS`, no unexplained v2/v3 diffs.

## [3.2.0] - 2026-08-01 — Engine v3 Migration Batch 2 (evidence-only scanners)

### Changed
- **Migrated scanners to evidence-only (Batch 2 of 6/19)**: `scanners/ports.py` (Open Ports), `scanners/http_methods.py` (HTTP Methods), `scanners/sensitive_files.py` (Sensitive Files) now set `use_engine_pipeline = True` and emit raw evidence only. Status, severity, confidence, verification, and execution state are derived exclusively by the v3 engine pipeline.
- **`tests/corpus.py`**: `ports_http_sensitive` scenario updated to raw findings mirroring the migrated scanners' output.
- **`tests/engine_tests.py`**: migrated-set assertion (6 modules), 13-on-legacy count, runtime contract tests for Sensitive Files / HTTP Methods, and an AST evidence-only guard for migrated scanner sources.

### Behavioral Changes (documented)
- HTTP Methods dangerous-method findings now report `FAIL` instead of the v2 manual `WARNING` override (evidence was already `confirmed`-level). Every dangerous method now captures its own response instead of reusing the last loop response.
- A server rejecting all tested methods now emits a `verified` "No dangerous HTTP methods are allowed" evidence item (keeps the prior `PASS` while satisfying the evidence-only contract).
- Open Ports stops incrementing the legacy `confirmations` counter.

### Quality
- `test_validation.py`: 0 errors / 0 warnings.
- Engine unit tests: 0 errors / 0 warnings.
- Golden regression: `REGRESSION=0` (PASS=3, WARNING=13 — all diffs explained).
- Live scan + session replay on `https://example.com`: `WARNING`, no unexplained v2/v3 diffs.

## [2.2.0] - 2026-07-30

### Added
- **SSTI Scanner**: `scanners/ssti.py` — Server-Side Template Injection detection across 5 template engines (Jinja2/Twig, Freemarker, Velocity, ERB/Ruby, Smarty). Dual-payload cross-validation (primary + confirm math expressions) eliminates false positives. Registered as page-level scanner (#19).
- **CSRF Scanner v2**: `scanners/csrf.py` rewritten to extract real POST form blocks, detect anti-CSRF token fields, submit test requests with and without the token, and report only when the server actually accepts tampered requests. Falls back to SameSite cookie inspection when no POST forms exist.

### Changed
- **`scanners/registry.py`**: Added `SSTIScanner` to imports, `PAGE_LEVEL_SCANNERS`, and `_SCANNER_NAME_MAP`. 19 scanners total.
- **`core/decision_engine.py`**: Added `SSTI Detection` to `STANDARDS` dict (CWE-1336, OWASP A03, CAPEC-35, CRITICAL severity) and `RECOMMENDATIONS` dict.
- **`test_validation.py`**: Updated registry counts (0→19, 0→12), added SSTI import/instantiation/registry/decision-engine tests.

### Quality
- 200+ validation checks pass (0 errors, 0 warnings).

## [2.1.0] - 2026-07-29

### Added
- **Jinja2 HTML Templates**: Extracted the ~990-line HTML report template from `core/reporter.py:build_html()` into `templates/report.html.j2`. The template now uses Jinja2 for rendering, making it editable without touching Python code.
- **Thread Safety Regression Tests**: Section 20 in `test_validation.py` covers B9 (concurrent `add_finding` with 50 threads) and B13 (no mutable class-level state across all 18 scanners).
- **`project_docs/SOP.md`**: Standard Operating Procedure document covering the full development workflow.

### Changed
- **`core/reporter.py`**: `build_html()` now attempts Jinja2 rendering first; falls back to the legacy inline f-string if Jinja2 is not installed.
- **`scanners/host_header.py`**: `TEST_HOSTS` converted from `list` to `tuple` for immutability.

### Fixed
- **B9 — Thread Safety on ScanResult**: Confirmed `ScanResult.add_finding()` is already protected by `threading.Lock()`. Added regression test with 50 concurrent threads (no lost findings).
- **B13 — Thread Safety in Scanner Instances**: Confirmed all scanners create fresh instances per invocation (no shared class-level mutable state). Regression test verifies all 18 scanners.

### Quality
- 200+ validation checks pass (0 errors, 0 warnings).
- Jinja2 fallback ensures backward compatibility when library is absent.

## [2.0.0] - 2026-07-28

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
