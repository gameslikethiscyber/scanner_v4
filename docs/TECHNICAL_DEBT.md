# Technical Debt Report

**Phase:** A8.9 — Migration Cleanup & Architecture Freeze
**Date:** 2026-08-01
**Companion spec:** `docs/ENGINE_ARCHITECTURE_V3.md`

Migrated to evidence-only: **19 of 19** (Headers/TLS/DNS — Batch 1; Open Ports /
Sensitive Files / HTTP Methods — Batch 2; Technology Detection / Security.txt /
Source Code Leaks / Cookies — Batch 3; CORS / CSRF / Host Header + SQL Injection /
XSS Detection — Batch 4; LFI / SSRF / Open Redirect / SSTI — Final Batch).

**A8.9 cleanup complete.** Every temporary migration compatibility layer was
removed from production (see §1/§2/§3), the v2 decision logic was **archived**
in `tests/v2_reference.py` (test-only; production never imports it), and the
single v3 pipeline became the only execution path. The regression harness now
compares the archived v2 against the v3 pipeline (gate: REGRESSION=0).
This document keeps the full history of what was removed; sections marked
"REMOVED in A8.9" are retained for the record.

This document catalogues everything introduced by, or left over from, the
incremental v2→v3 engine migration. Each entry is tagged with its lifetime:

- **TEMPORARY** — exists only for incremental migration / parity testing; removed
  at a defined phase (Batch 6 / A9 / A10).
- **PERMANENT** — the v3 architecture's intended shape; must be preserved.

---

## 1. Migration compatibility layers

Everything that existed *only* to let the v2 and v3 paths coexist during the
incremental migration. **All rows below were REMOVED in A8.9** (kept here for
the record); the archived v2 logic lives in `tests/v2_reference.py`.

| Layer | Location | Lifetime | Notes |
|---|---|---|---|
| `BaseScanner.use_engine_pipeline` class flag | `scanners/base.py:73` | ~~TEMPORARY → removed at Batch 6~~ **REMOVED in A8.9** | The batch boundary. Migrated scanners set `True`; the flag is deleted once all 19 scanners are migrated and `run()` always uses the pipeline. |
| `run()` legacy branch (`DecisionEngine.decide()`) | `scanners/base.py:99-100` | ~~TEMPORARY → removed at Batch 6~~ **REMOVED in A8.9** | Kept until Batch 6 cleanup; all 19 scanners now set `use_engine_pipeline = True`, so no live scanner runs through it. |
| `run_engine_pipeline(respect_existing=True)` parity mode | `core/pipeline.py:35` | ~~TEMPORARY → default flips to `False` at Batch 6; parameter removed at A9~~ **REMOVED in A8.9** | `True` reproduced v2 scanner-preset severity for the harness; migrated scanners always passed `False`. Now gone — the module map is authoritative everywhere. |
| `verification_class` + report-vocabulary `verification_status` | `core/finding.py:189`, `core/pipeline.py:66-71` | PERMANENT (kept until A10, then reassessed) | Dual attribute. `verification_status` = v2 report vocabulary; `verification_class` = raw v3 band. Once reporters/GUI consume `Assessment` only (A10), the pipeline may drop the dual write and store the v3 band once. |
| `Finding.add_evidence()` v2 auto-assessment side effect | `core/finding.py:231-348` | ~~TEMPORARY → removed after Batch 6~~ **REMOVED in A8.9** | `add_evidence` now only appends; confidence/verification/matched-rules are written exclusively by `ConfidenceEngine`/`VerificationEngine` (pipeline) or the archived `v2_apply_evidence_assessment`. |
| `respect_existing` semantics in `SeverityEngine.assess` | `core/severity_engine.py:61-86` | ~~TEMPORARY → removed after Batch 6~~ **REMOVED in A8.9** | v2 parity mode only. |
| `_VERIFICATION_REPORT_MAP` (`confirmed`→`verified`) | `core/pipeline.py:168` | TEMPORARY → removed at A10 | Report vocabulary mapping; also mirrored in `tests/diffing.py`. |
| `DecisionEngine.SEVERITY_BY_MODULE` re-derivation in `SeverityEngine` | `core/severity_engine.py:32` | **PERMANENT (already fixed in A8.5)** | Now `SeverityEngine.SEVERITY_BY_MODULE is DecisionEngine.SEVERITY_BY_MODULE` — single source of truth. |
| `_determine_status` / `_ensure_reason_recommendation` / `_reclassify_positive_warnings` | `core/pipeline.py` + `core/decision_engine.py` | ~~TEMPORARY duplication~~ **REMOVED in A8.9** | Byte-identical implementations. The pipeline copies are the v3 owner; the `DecisionEngine` copies (with `decide()`) were archived to `tests/v2_reference.py` (`v2_decide` + helpers). |
| `tests/corpus.py::_finding` legacy helper | `tests/corpus.py:27` | ~~TEMPORARY → removed after Batch 6~~ **REMOVED** (Final Batch) | Produced legacy-style findings (pre-set status/severity). Migrated modules use `_raw_finding`; the legacy helper disappeared with the last batch. |

## 2. Remaining legacy code

Code that predates the v3 engines. Rows marked "REMOVED in A8.9" were deleted;
the v2 assessment logic was archived to `tests/v2_reference.py` (test-only).

| Legacy code | Location | Still used by | Lifetime |
|---|---|---|---|
| `DecisionEngine.decide()` + all `_*` helpers | ~~`core/decision_engine.py:276-500`~~ → **`tests/v2_reference.py`** (`v2_decide` + `V2DecisionEngine`) | no production callers; regression harness (`run_v2`) | ~~TEMPORARY → deleted at Batch 6~~ **ARCHIVED in A8.9** — never imported by production. |
| `DecisionEngine` metadata provider (`STANDARDS`, `RECOMMENDATIONS`, `CVSS_DESCRIPTIONS`) | `core/decision_engine.py` | **PERMANENT** — it is the standards metadata single source of truth consumed by `SeverityEngine` and the pipeline | Moved (not deleted) — considered part of the v3 core. |
| `RiskCalculator.calculate` | `core/decision_engine.py` | `ScanResult.calculate_dynamic_risk_score` / `calculate_risk_breakdown` (un-assessed fallback only) | TEMPORARY → **A9**: production orchestrators read risk from the `Assessment`; the legacy methods now delegate to the stored `Assessment` when present and fall back to `RiskCalculator` only for un-assessed results. `RiskCalculator` removed at A10. Byte-identical to `RiskEngine.calculate` (verified by tests). |
| `ScanResult.get_statistics()` | `core/finding.py:1137+` | un-assessed fallback; `tests/engine_paths.run_v2` | TEMPORARY → **A9**: delegates to `Assessment.statistics` when an `Assessment` is stored (production consumers now always hit the Assessment dict). Removed at A10. |
| `ScanResult.get_coverage()` / `get_execution_states()` | `core/finding.py:641, 776` | un-assessed fallback | TEMPORARY → **A9**: delegate to the stored `Assessment`/`CoverageEngine.report` when assessed. Removed at A10. |
| `ScanResult.get_overall_severity()` | `core/finding.py:968` | un-assessed fallback | TEMPORARY → **A9**: delegates to `Assessment.overall_tier` when assessed. Removed at A10. |
| `Finding.compute_execution_state()` | ~~`core/finding.py:386`~~ | ~~reporters/GUI via `to_dict()`, `get_execution_states()`~~ → **`tests/v2_reference.v2_compute_execution_state`** | ~~TEMPORARY → removed after Batch 6~~ **ARCHIVED in A8.9** — `CoverageEngine.classify_execution_state` is the single owner; the archived v2 diverged on UNKNOWN findings. |
| `Finding._update_verification_status`, `_highest_evidence_level`, `_build_confidence_explanation`, `collect_matched_rules` | ~~`core/finding.py`~~ → **`tests/v2_reference.py`** | v2 auto-assessment chain | ~~TEMPORARY → removed with the `add_evidence` side effect (§1)~~ **ARCHIVED in A8.9**. |
| `BaseScanner.create_safe_finding` / `create_vulnerable_finding` | ~~`scanners/base.py:159-180`~~ | no callers (all 19 scanners migrated) | ~~TEMPORARY → removed after Batch 6~~ **REMOVED in A8.9** (they assigned status/severity/confidence outside the engines). |
| Backend OAIST confirmation write | ~~`backend/app/scan_runner.py:91-95`~~ | backend scans | ~~TEMPORARY → A9 converts to an engine hook~~ **RESOLVED in A9** — see §3.4. Now `EvidenceBuilder().exploited(...)` evidence + pipeline assessment; no direct field overrides. |
| `ScanResult.run_correlation()` / `CorrelationEngine.correlate()` (mutating) | `core/finding.py:809`, `core/correlation_engine.py:111` | no production callers (pipeline `_apply_correlation_pipeline`); `run_correlation()` returns `[]` on assessed results | TEMPORARY → **A9**: consumers switched to `run_assessment_pipeline` (which applies correlation once, idempotently). Mutating `correlate()` removed at A10; non-mutating `correlation_payloads()`/`_match_rules()` are PERMANENT. |
| `_aggregate_test_counters` / `get_payload_testing_status` on `ScanResult` | `core/finding.py:712, 945` | `AssessmentEngine._statistics` | TEMPORARY → **RESOLVED at A9**: `AssessmentEngine._statistics` is the single statistics owner; `ScanResult.get_statistics()` delegates to it when an `Assessment` is stored (un-assessed fallback retained until A10). |

## 3. Legacy side effects (assignment outside the engines)

Requirement: scanners collect evidence; engines assign status/confidence/
verification/severity. Sections 3.1–3.3 and 3.5–3.6 were **REMOVED / ARCHIVED in
A8.9**; §3.4 (backend post-pipeline writer) was **RESOLVED in A9** (see §3.4).

### 3.1 Confidence / verification — `Finding.add_evidence()` — **REMOVED in A8.9**
`add_evidence()` is now a plain append. The v2 auto-assessment chain
(`_update_confidence_from_evidence` / `_update_verification_status` /
`_highest_evidence_level` / `_build_confidence_explanation` /
`collect_matched_rules`) is archived as `v2_apply_evidence_assessment()` in
`tests/v2_reference.py`. The v3 pipeline is the only assessment writer.

### 3.2 Status / severity / confidence — scanner helpers — **REMOVED in A8.9**
`BaseScanner.create_safe_finding` / `create_vulnerable_finding` deleted; no
remaining callers. All 19 scanners emit evidence only.

### 3.3 Severity / status — legacy corpus helper — **REMOVED (Final Batch)**
`tests/corpus.py::_finding` (pre-set status/severity) deleted; `_raw_finding`
is the only corpus builder.

### 3.4 Verification / confidence — backend OAIST confirmation — **RESOLVED in A9**
`backend/app/scan_runner.py`. Previously wrote `verification_status="verified"`,
`confidence=100` for findings with OAST interactions (backend ORM model, after
the pipeline). **A9 converted it to an engine hook**: matching interactions now
append `EvidenceBuilder().exploited(...)` evidence to the finding and the single
assessment pipeline re-assesses verification/confidence/severity from that
evidence. No direct field overrides remain.

### 3.5 Execution state — `Finding.compute_execution_state()` — **ARCHIVED in A8.9**
Now `tests/v2_reference.v2_compute_execution_state`. `CoverageEngine.
classify_execution_state` is the single owner (pipeline + Assessment + the
read-only `Finding.execution_label` / `ScanResult.get_execution_states`
fallback all use it).

### 3.6 Severity preset — legacy scanner writes — **REMOVED in A8.9**
The `respect_existing` parameter (pipeline + `SeverityEngine.assess`) is
deleted; the module map is authoritative everywhere. No scanner sets a preset
anymore (all 19 migrated).

### 3.7 Behavioural change log (Batch 2)
| Module | v2 output | v3 (migrated) output | Justification |
|---|---|---|---|
| `HTTP Methods` | dangerous methods → `WARNING` | dangerous methods → `FAIL` | The scanner always emitted `confirmed`-level `request_response` evidence; the v2 scanner *manually overrode* the natural confirmed→FAIL assessment to WARNING. Batch 2 removed the override, so the engine now derives FAIL from the confirmed evidence. Both v2 and v3 engine paths agree on the migrated input (regression gate green). |
| `HTTP Methods` | last-loop `resp` reused for every dangerous-method evidence | each dangerous method captures **its own** response | Fixed a pre-existing evidence-accuracy bug: the old code attached the final loop response to every dangerous method. |
| `HTTP Methods` | server rejecting every method → `PASS`, no evidence | same `PASS`, plus a `verified` "No dangerous HTTP methods are allowed" evidence | Evidence-only contract requires ≥1 evidence item; level chosen so the engine derives the original PASS. |
| `Open Ports` | `confirmations += 1` legacy counter | not incremented (removed) | Legacy counter; Batch-1 migrated scanners already stopped setting it. Not consumed by the engines or reports. |
| `Sensitive Files` / `Open Ports` / `HTTP Methods` | status/severity preset inside `scan()` | `scan()` leaves status `UNKNOWN` / severity `NONE`; engine pipeline derives everything | Core evidence-only requirement (Phase A8). |

### 3.8 Behavioural change log (Batch 3)
| Module | v2 output | v3 (migrated) output | Justification |
|---|---|---|---|
| `Cookies Security` | single pre-classified `issues` list (strings like "missing Secure flag") | **one evidence item per cookie attribute** (Secure / HttpOnly / SameSite / Prefix / Expiration / Domain / Path); attribute present → `verified`, absent → `likely` | Evidence-only contract + improved normalization: each attribute is independently assessable. `CookieAnalysis.issues` removed from `core/response_analyzer.py`; per-attribute data now carried in the dataclass. |
| `Cookies Security` | `PASS` with no cookies | `PASS` with a `verified` "No cookies found" evidence, `tests_performed = 0` | Keeps `execution_state = NOT_APPLICABLE` (test_validation SOP #4 depends on Cookies PASS with 0 tests). |
| `Cookies Security` | issue ordering unspecified | issue items sorted first so the **lead evidence is an issue** | Load-bearing: the v3 positive-observation rule (SOP #6) never reclassifies a WARNING whose first evidence is an issue; verified by smoke test (insecure cookie stays warning/low). |
| `Security.txt` | single pre-classified finding | state machine: `missing` (neither `/`.well-known/security.txt` nor `/security.txt` returns 200) → `likely` evidence; `found` → `verified` accessible evidence + per-problem `likely` evidence. Fingerprint `security_txt_state` distinguishes `valid` / `accessible` / `invalid` (empty body) / `malformed` (no parseable `Key: value` directives). | Improved normalization — the v2 scanner collapsed all failure modes into one WARNING; v3 exposes the exact reason (missing Contact, past Expires, malformed, empty). |
| `Source Code Leaks` | single flat pattern list (14 patterns) | **6 categories / 21 patterns** (`CATEGORIES` dict): API Keys + Configuration Disclosure = `confirmed`-level via `capture_http_evidence`; Debug Information + Emails + Comments + Source Maps = `likely` via `eb.likely`. Fingerprint `leak_categories` + `detection_methods`. | Improved normalization: leak type is now explicit and drives evidence level (API-key exposure is a confirmed finding, code comments are a likely one). Clean page emits a `verified` no-leak evidence. |
| `Technology Detection` | single merged fingerprint string | **one `verified` evidence per technology**, `raw_data = {technology, source, signal, detail}` (source `body` or `header`); fingerprint keeps `detected_technologies` + `version_hints` | Structured provenance lets the engine weigh each detection independently; `tests_performed = 16` (one per pattern set). No-detection emits a `verified` "No specific technologies detected" evidence. |
| `Technology Detection` | `detect_technologies` consumed by scanners | `ResponseAnalyzer.detect_technology_fingerprints()` added; `_detect_technologies` now delegates to it | Single fingerprint source; downstream consumers (SqliScanner etc.) unchanged. |
| `Technology Detection` / `Security.txt` / `Source Code Leaks` / `Cookies` | status/severity/confidence preset inside `scan()` | `scan()` leaves status `UNKNOWN` / severity `NONE`; engine pipeline derives everything | Core evidence-only requirement (Phase A8). |

### 3.9 Behavioural change log (Batch 4 Part 1)
| Module | v2 output | v3 (migrated) output | Justification |
|---|---|---|---|
| `CORS Configuration` | single binary rule: permissive ACAO → WARNING/FAIL, else PASS | **multi-signal** (`cors_signals` fingerprint): `wildcard_credentials`, `wildcard_origin`, `null_origin`, `origin_reflection` (confirmed/likely per signal) + `credentials_with_acao` (support) + OPTIONS `preflight_confirmed` probe. Support signals emit only when a core signal already exists; `Vary: Origin` absence is recorded as metadata (`vary_missing_origin`), **not** an evidence item — a separate `possible` evidence would cap the finding's confidence at 60 and undercut multi-signal agreement. Clean policy → `verified` restrictive-policy evidence. `tests_performed = 5` (4 origins + preflight). | Evidence-only contract + multi-observation verification: each test origin is an independent observation; confidence rises only when multiple signals agree. |
| `CSRF Protection` | single binary rule: token present → PASS, absent → FAIL | **multi-observation per POST form**: `no_token` (confirmed), `cross_origin_accepted` (confirmed — Origin/Referer gating probe), `token_not_enforced` (confirmed — server accepts the request without the token), `token_enforced` (verified positive). No POST forms → `verified` evidence preserving `NOT_APPLICABLE`; `same_site_cookies` folded into the fingerprint. Observations sorted issues-first so a FAIL's lead evidence is never a reassuring observation. `tests_performed = max(len(post_forms), 1)`. | Evidence-only contract + avoids binary pass/fail: token *presence* and token *enforcement* are independent observations; the behavioural token-removal test (`token_not_enforced`) is the key upgrade over the old string-presence heuristic. |
| `Host Header Injection` | single pre-classified finding | **multi-observation per test host** (`host_header_observations` fingerprint): `body_reflection`, `redirect_location`, `generated_url` (confirmed) + `cache_poisoning_risk` (likely — response differs vs baseline AND Vary lacks Host/Origin AND the injected host value actually appears in the differing response). `cache_poisoning_risk` is gated on host-value presence because a bare content change under a foreign Host is normal virtual-host routing, not poisonable content — without the gate a clean vhost'd site (e.g. example.com) becomes a false WARNING. Clean → `verified` no-injection evidence. `tests_performed = 4`. | Evidence-only contract + "no classification on one response alone": each test host is an independent observation; cache poisoning requires host-derived content reaching a shared cache. |
| `CORS` / `CSRF` / `Host Header` | status/severity/confidence preset inside `scan()` | `scan()` leaves status `UNKNOWN` / severity `NONE`; engine pipeline derives everything | Core evidence-only requirement (Phase A8). |

### 3.10 Behavioural change log (Batch 4 Part 2)

| Module | v2 output | v3 (migrated) output | Justification |
|---|---|---|---|
| `SQL Injection` | single pre-classified finding, one exploit payload | **multi-technique evidence-only** (`sqli_signals[]` + `database` fingerprint): `error_based` (DB signature matched on the primary payload **and** reproduced with a second, distinct payload — per-DB signatures mysql/postgresql/mssql/oracle/sqlite), `boolean_based` (true/false responses differ by ≥40 bytes length, status, or `<0.8` Jaccard similarity via `ResponseAnalyzer.body_similarity`, **reconfirmed with the independent `'/**/OR/**/1=1-- -` comment-injection pair**), `time_based` (delay ≥ `max(baseline+4, 6)s` from a 3-sample median baseline, **retry-consistent** — second request reproduces the delay, variance recorded; SLEEP/pg_sleep/WAITFOR payloads). Every observation carries `request_response` evidence with technique/matched_rule/database/reliability/reproducible/confirm_payload/timing/comparison in `raw_data`; observations deduped per parameter. **2+ techniques** add a `cross_validation` (verified) evidence so multi-signal agreement raises confidence; single-technique caps at `likely`/80. | Evidence-only contract + no single-payload confirmation: each technique requires a *different* second payload to reproduce, so a lone error string or a one-off delay is not a finding. Multi-technique agreement is the only path to `verified`. |
| `XSS Detection` | single pre-classified finding, one regex pass | **multi-context evidence-only** (`xss_signals[]` + `reflected_params` fingerprint): three families `html` / `attribute` / `javascript`, each tested per parameter with a primary payload and **reconfirmed with a second distinct payload + an independent context regex** (no single-regex confirmation). Marker AND context must both hold; context patterns are **executable-location-precise** (the `alert(` must sit inside the same tag/script, e.g. `<script[^>]*>\s*alert\s*\(`), so a page that merely echoes input but HTML-escapes it (`&lt;script&gt;`) never matches. Attribute context requires a literal quote breakout / unquoted injection — escaped `&quot;`/`&gt;` cannot trip it. **2+ contexts** add `cross_validation` (verified) evidence. `encoded` decoding probes are `likely` support evidence emitted only alongside a confirmed core context (never a standalone finding, and never `possible` — a `possible` evidence would cap confidence at 60 via the level-cap chain). Fingerprint `xss_signals[]` records context per parameter; clean → `verified` no-XSS evidence. | Evidence-only contract + confidence rises only with multiple independent indicators: an event-handler pattern that fires on escaped output is a false positive, so context regexes must prove executable delivery, and single-regex confirmation is removed. |
| `SQL Injection` / `XSS Detection` | status/severity/confidence preset inside `scan()` | `scan()` leaves status `UNKNOWN` / severity `NONE`; engine pipeline derives everything | Core evidence-only requirement (Phase A8). |
| `SQL Injection` / `XSS Detection` | no-params case → `skipped`/none | no-params emits `verified` "no parameters to test" evidence + `tests_passed = 0` (not `f.skipped`), preserving the v2 `pass/none/75/verified/not_applicable` snapshot exactly | Bare `f.skipped` without evidence yields v2 `none` vs v3 `info`; the verified-evidence pattern keeps both engine paths byte-identical. |

### 3.11 Behavioural change log (Final Batch: LFI / SSRF / Open Redirect / SSTI)

| Module | v2 output | v3 (migrated) output | Justification |
|---|---|---|---|
| `LFI Detection` | single pre-classified finding | **multi-technique evidence-only** (`lfi_signals[]` + `files_disclosed` fingerprint): `traversal` (known-file content signature reproduces on two distinct paths), `disclosure` (≥2 distinct sensitive-file markers on independent payloads), `os_fingerprint` (POSIX vs Windows markers), `null_byte` (a `%00` payload discloses a file the plain path does not — PHP < 5.3.4), `encoding_bypass` (URL / double-URL / backslash / dot-overslash variants disclose a file, reconfirmed with a second variant), `error_signature` (include/require/failed-to-open strings, reproduced twice). Adaptive depth `_guess_depth()` (3–8). **2+ techniques** add `cross_validation` (verified) evidence; observations carry technique/matched_rule/file/os in `raw_data`. No params → `verified` "no parameters to test". | Evidence-only contract + no single-path confirmation: every technique requires a *different* second payload to reproduce, so one echoed `root:x:` is not a finding. |
| `SSRF Detection` | single pre-classified finding | **multi-technique evidence-only** (`ssrf_signals[]` fingerprint): `metadata` (cloud metadata markers return through the parameter, reproduced on a second metadata endpoint — 169.254.169.254 / Google computeMetadata), `internal_access` (response to a private address differs from baseline by >500 bytes or status, reproduced on a second address), `error_signature` (URL-fetch error strings like `Connection refused` reproduced), `redirect` (server follows a payload URL that redirects to an internal/attacker target), `oast` (out-of-band interaction when an OAIST manager is configured — never a hard failure without one). **2+ techniques** add `cross_validation` (verified) evidence. No params → `verified` no-params evidence. | Evidence-only contract + baseline-differential confirmation: a lone echoed response or error string is not a finding without a second, independent reproduction. |
| `Open Redirect` | single pre-classified finding | **multi-technique evidence-only** (`open_redirect_signals[]` fingerprint): `absolute`, `relative`, `protocol_relative`, `encoded`, `double_encoding` (each confirmed when two distinct payloads yield an off-host `Location`, with decoding normalization in `_decoded_location`), plus `redirect_chain` ordering slot. **2+ techniques** add `cross_validation` (verified) evidence. No params → `verified` no-params evidence. | Evidence-only contract + dual-payload confirmation per vector: `Location` reflection must be reproduced with a second, independent payload before it is reported. |
| `SSTI Detection` | single pre-classified finding | **multi-engine evidence-only** (`ssti_signals[]` + `engines` fingerprint): `arithmetic_evaluation` per engine (jinja2 / twig / freemarker / velocity / handlebars / smarty / erb) confirmed only when **two distinct math expressions** evaluate to the expected results (`{{7*7}}`→49 AND `{{8*9}}`→72), ruling out numbers already present in the page; syntax families that share `{{ expr }}` (jinja2/twig/handlebars) are deduped so one evaluation never claims three engines; `error_fingerprint` / `engine_fingerprint` support evidence. **2+ engines** add `cross_validation` (verified) evidence. No params → `verified` no-params evidence. | Evidence-only contract + dual-expression confirmation: a single echoed result is coincidence; only two independent evaluations across two constructions confirm an engine. |
| `LFI` / `SSRF` / `Open Redirect` / `SSTI` | status/severity/confidence preset inside `scan()` | `scan()` leaves status `UNKNOWN` / severity `NONE`; engine pipeline derives everything | Core evidence-only requirement (Phase A8). This closes the migration: **19/19 scanners evidence-only, 0 on `decide()`**. |

## 4. Deprecated APIs

| API | Deprecated by | Removal |
|---|---|---|
| `DecisionEngine.decide()` | `BaseScanner.run()` → `run_engine_pipeline` | **REMOVED in A8.9** → archived as `tests.v2_reference.v2_decide` |
| `DecisionEngine._determine_status/_determine_severity/_calculate_cvss/_assign_impact/_assign_standards/_determine_exploitability/_generate_verify_commands/_populate_replay_data` | `core/pipeline.py` + engines | **REMOVED in A8.9** → archived as v2 helpers |
| `RiskCalculator` | `core/risk_engine.py` | A10 (follows `get_statistics`) |
| `ScanResult.get_statistics/get_coverage/get_execution_states/get_overall_severity/calculate_dynamic_risk_score/calculate_risk_breakdown` | `Assessment` / engines | A9: production consumers switched to `Assessment`; legacy methods retained as **delegations** (read the stored `Assessment`, fall back to inline only for un-assessed results) until A10 removes them |
| `ScanResult.run_correlation()` | pipeline `_apply_correlation_pipeline` | A9: production consumers switched to `run_assessment_pipeline`; method returns `[]` on assessed results. Removed at A10 |
| `CorrelationEngine.correlate()` (mutating) | `correlation_payloads()` | A9: no production caller (pipeline uses `_apply_correlation_pipeline`) |
| `Finding.compute_execution_state()` | `CoverageEngine.classify_execution_state` | **REMOVED in A8.9** → archived as `v2_compute_execution_state` |
| `Finding._update_confidence_from_evidence/_update_verification_status/_build_confidence_explanation/_highest_evidence_level` | `ConfidenceEngine` / `VerificationEngine` | **REMOVED in A8.9** → archived in `v2_apply_evidence_assessment` |
| `BaseScanner.create_safe_finding/create_vulnerable_finding` | engines | **REMOVED in A8.9** |
| `Status.SAFE` / `Status.VULNERABLE` aliases | `Status.PASS` / `Status.FAIL` | A10 (check GUI/reporter usage first) |
| `EngineScanResult` legacy counters (`module_name`, `findings`, `confirmations`, `heuristics`, `false_positive_risk`, `duration_ms`, `meta`) | — | A10 |

## 5. Engine TODOs

### A9 — orchestrator wiring (assessment integration) — **COMPLETED**
- [x] Wire `gui/services/scan_worker.py`, `backend/app/scan_runner.py`, `main.py`
      to `run_assessment_pipeline()` (via the idempotent `ScanResult.assess()`
      gateway) and persist the `Assessment` on `ScanResult.assessment`. All
      three orchestrators now produce exactly one immutable `Assessment` per
      scan and read all risk/severity/confidence/coverage from it.
- [x] `scan_runner.py` re-aggregates safe findings *after* the pipeline:
      `aggregate_safe_findings()` runs after `run_assessment_pipeline()`, so
      status-determined findings are collected correctly.
- [x] Convert the backend OAIST confirmation write (§3.4) into an evidence +
      pipeline hook (`EvidenceBuilder().exploited(...)`; pipeline derives
      verification/confidence/severity).
- [x] `AssessmentEngine._statistics` remains the single owner of statistics;
      `ScanResult.get_statistics()` now delegates to it when an `Assessment`
      is stored. The `_aggregate_test_counters` / `get_payload_testing_status`
      legacy paths are superseded by the Assessment statistics dict for
      production consumers (retained as un-assessed fallback until A10).
- Remaining at A10: delete the delegation methods, `RiskCalculator`,
  `run_correlation()`, `_VERIFICATION_REPORT_MAP`, and the dual
  `verification_class` / `verification_status` write once reporters/GUI/CLI
  consume the `Assessment` exclusively.

### A10 — consumers
- [ ] `core/reporter.py`, `core/pdf_reporter.py`, `templates/report.html.j2`
      consume `Assessment` instead of `ScanResult.get_statistics()`.
- [ ] Decide the fate of the dual `verification_class`/`verification_status`
      write (§1) once report consumers are engine-only.
- [ ] Drop the `confirmed`→`verified` report-vocabulary map from the pipeline.
- [ ] Remove `RiskCalculator` with `get_statistics`.

### Batch 6 / A8.9 — legacy removal (migration complete: all 19 scanners evidence-only)
- [x] Migrate LFI Detection, SSRF Detection, Open Redirect, SSTI Detection to
      evidence-only (Final Batch, 4 scanners → 19/19). Regression gate green
      (0 REGRESSIONS), `engine_tests.py` migrated set = 19, legacy = 0.
- [x] Delete `DecisionEngine.decide()` and all legacy `_*` helpers.
      **Archived** as `tests/v2_reference.v2_decide` / `V2DecisionEngine`.
- [x] Delete the `add_evidence` auto-assessment side effect; `ConfidenceEngine` /
      `VerificationEngine` become the only confidence/verification writers
      (**archived** as `v2_apply_evidence_assessment`).
- [x] Remove `use_engine_pipeline` flag; `BaseScanner.run()` always pipelines.
- [x] Remove `create_safe_finding` / `create_vulnerable_finding`.
- [x] Remove `Finding.compute_execution_state()` (**archived** as
      `v2_compute_execution_state`).
- [x] Remove `respect_existing` from pipeline + `SeverityEngine`; the module map
      is authoritative everywhere.
- [x] Remove the corpus `_finding` helper. (Done with the Final Batch — helper
      already deleted; `_raw_finding` is the only corpus builder.)

### Known edge case
- A raw finding with **no evidence and status UNKNOWN** gets severity `INFO` from
  the pipeline (`SeverityEngine`) whereas legacy `decide()` returns `NONE`
  (early return). Not reachable by current scanners (all emit at least one
  evidence item), so no parity diff. Documented here for the removal of `decide()`.

## 6. What is now permanent

- The engine pipeline order (Evidence → Confidence → Verification → Severity →
  Correlation → Risk → Coverage → Assessment → Executive Summary).
- `core/pipeline.py` `run_engine_pipeline` / `run_assessment_pipeline` as the
  single entry point (`BaseScanner.run()` delegates to it per finding). **There
  is only one execution path** (A8.9 freeze).
- Engines as the only assessment writers; `CoreEngine` never mutates evidence;
  `add_evidence` only appends.
- `DecisionEngine.STANDARDS/RECOMMENDATIONS/CVSS_DESCRIPTIONS` as the metadata
  single source of truth.
- `CoverageEngine.classify_execution_state` as the single execution-state owner
  (pipeline + Assessment + read-only `Finding.execution_label` fallback).
- `SeverityEngine` severity map derived once from `DecisionEngine.STANDARDS`
  (identity check in `engine_tests`).
- Non-mutating `CorrelationEngine.correlation_payloads()` / `_match_rules()`.
- `Assessment` as the immutable output contract; `statistics` dict keeps the
  v2 shape for backward compatibility.
- **`tests/v2_reference.py`** — the archived v2 decision logic, test-only;
  production never imports it.

## 7. Guardrails (how debt is kept from growing)

- `tests/engine_tests.py` — engine unit tests + architecture checks: single
  source of truth (severity map identity), engine/legacy table parity, no
  GUI/scanner imports in `core/`, no top-level import cycles, migrated-scanner
  evidence-only contract (runtime `scan()` checks **and** an AST guard over all
  scanner sources that rejects any direct
  `finding.status/severity/confidence/verification_status/verification_class/
  execution_state/confidence_factors/cvss_score/cwe_id` assignment) and an
  explicit `hasattr(use_engine_pipeline) == False` check.
- `tests/v2_reference.py` — the archived v2 decision logic. Test-only; a code
  audit + import guard keeps production (core/scanners/gui/backend) from ever
  importing it.
- `tests/regression_runner.py` — golden v2↔v3 parity (archived v2 vs v3
  pipeline); any new unexplained behaviour change fails the gate (exit 1).
- `tests/live_scan_runner.py` — live parity on real scans.
- `test_validation.py` — 0 errors / 0 warnings required after every phase.
