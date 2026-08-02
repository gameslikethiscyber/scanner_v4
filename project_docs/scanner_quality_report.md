# Scanner Quality Report — Phase 3.10 (v4.9.0)

Scope: the "Scanner Quality Pass". Every scanner implemented up to this point
was reviewed; the four highest-value detection-accuracy improvements were made
and benchmarked; the remaining five were audited and formally documented as
**unchanged** because the cost/benefit did not justify local deterministic
refactors. This report is the final quality gate before Phase 4.

---

## 1. Benchmarked improvements (this pass)

Four scanners were rewritten and every change is justified by a reproducible
Before/After benchmark against deterministic local fixtures, plus a dedicated
`test_validation.py` section.

### 1.1 Cookies Security (Phase 3.9, carried forward) — v4.8.0
| Metric | Before | After |
|---|---|---|
| Detection rate | 0% (5 FN / 0 TP / 3 TN) | 100% (5 TP / 0 FP / 0 FN / 3 TN) |
| Precision | — | 100% |

Key fix: the `requests` cookie jar silently drops out-of-scope cookies
(e.g. `Domain=com`), hiding `/broad_domain`. Raw `Set-Cookie` harvest plus
session/prefix discrimination closed the blind spot. Validation §42.

### 1.2 Sensitive Files — v4.9.0
| Metric | Before | After |
|---|---|---|
| Detection | 75% (3 TP / 1 FN) | 100% (3 TP / 0 FN) |
| Precision | 75% (1 FP) | 100% (0 FP) |

Fixes: removed benign public files (robots.txt, README, LICENSE, package.json,
sitemap.xml, Makefile, .gitignore) from the exposure catalogue; added the
`_raises_wrapper_page` guard so a 200-with-HTML-"Not Found" custom error page is
not treated as exposure. Benchmark: `benchmarks/sensitive_files_benchmark.py`.
Validation §43.

### 1.3 HTTP Methods — v4.9.0
| Metric | Before | After |
|---|---|---|
| Detection | 80% (4 TP / 1 FN) | 100% (4 TP / 0 FN) |
| Precision | 80% (1 FP) | 100% (0 FP) |

Fixes: allowance is now defined as **2xx executed or 401 auth-gated only** —
3xx redirects (previously counted as `allowed`), 404/403/405 and 5xx no longer
signal a permitted method. Dangerous-method set (PUT/DELETE/TRACE/CONNECT/
PATCH/PURGE) drives dynamic `http_methods_confidence`. Benchmark:
`benchmarks/http_methods_benchmark.py`. Validation §44.

### 1.4 Headers Security — v4.9.0
Duplicate-evidence elimination. Before, a weak CSP was reported **twice**
(aria CSP + generated variance cascade); now single-source fingerprint
(`header_present` / `header_missing` / `header_issues` / `header_confidence`)
emits each issue exactly **once**. Missing-header severity is weighted by
`MISSING_SEVERITY`. Benchmark `benchmarks/headers_benchmark.py`. Validation §45.

### 1.5 Source Code Leaks — v4.9.0
| Metric | Before | After |
|---|---|---|
| Detection (of real leaks) | 0% on fixtures | 100% (4 TP / 0 FN) |
| Precision (ambient noise) | — | 100% (0 FP) |

Key change: ambient/informational categories (**Emails, Comments, Debug
Information, Source Maps**) are only emitted alongside a real confirmed leak
(API Keys / Configuration Disclosure), so an ordinary contact page with an email
or a page with a stack trace is no longer flagged. Confirmed leaks dedupe to one
category each. Token-FP: added legitimate AWS/Azure/GCP access-key + `AKIA...`
patterns eliminated a FN. Benchmark
`benchmarks/source_leaks_benchmark.py`. Validation §46.

---

## 2. Scanners audited and left unchanged (documented rationale)

These were reviewed in depth. They already meet the evidence/confidence
standards, or a deterministic local benchmark cannot add value:

| Scanner | Verdict | Rationale |
|---|---|---|
| **Technology Detection** (`tech_detect.py`) | Unchanged | Pure detection/identification via `ResponseAnalyzer.detect_technology_fingerprints`. Emits `verified` evidence only when a signature matches; false-positive ceiling is low (a signature match is factual). No FP/FN accuracy model to improve locally; adding one would overfit to an arbitrary signature fixture. |
| **DNS Security** (`dns_scanner.py`) | Unchanged | Network-bound on live resolver; not deterministically testable offline. Current logic (per-record-type try/except, resolved sets, fingerprint) is conservative and already structured evidence. A local benchmark would require mocking `dns.resolver` — a test concern, not a scanner-quality concern. |
| **TLS/SSL Security** (`tls.py`) | Unchanged | Network-bound real TLS handshake + certificate chain analysis. Handled correctly (protocol version, cert expiry, key-size, forward secrecy, HSTS, CRIME). Fixtures would require a local TLS server and a trusted PKI; the evidence grading (verified/likely/confirmed) is already severity-correct. Deferred to a network-enabled test harness in Phase 4. |
| **Open Ports** (`ports.py`) | Unchanged | Network-bound TCP `connect_ex` with timeouts over a fixed well-known-port map. Deterministic only against a fixture you control; the scanner logic is already minimal and FP-free (a successful TCP connect is factual). Scheduling thread-pool limits are operational, not quality. |
| **Host Header Injection** (`host_header.py`) | Unchanged | Already the most hardened of the set: multi-observation (body reflection, redirect Location, generated absolute URL, cache-poisoning risk with Vary gate). Exactly the evidence-quality model this pass promotes. No measurable local gain. |

These five are network-bound or already-compliant; none has a local FP/FN
measurement that a rewrite would improve without inventing a contrived fixture.

---

## 3. Project-wide scanner status (summary)

| Scanner | Phase | Outcome |
|---|---|---|
| Cookies | 3.9 | Improved, 100% / 100% |
| Sensitive Files | 3.10 | Improved, 100% / 100% |
| HTTP Methods | 3.10 | Improved, 100% / 100% |
| Headers | 3.10 | Improved, dedup/exact-once |
| Source Code Leaks | 3.10 | Improved, 100% / 100% |
| Technology Detection | 3.10 | Audited — unchanged |
| DNS Security | 3.10 | Audited — unchanged (network-bound) |
| TLS/SSL Security | 3.10 | Audited — unchanged (network-bound) |
| Open Ports | 3.10 | Audited — unchanged (network-bound) |
| Host Header Injection | 3.10 | Audited — already compliant |

---

## 4. Gate status (all green)

- `test_validation.py` — **0 errors**, 0 real failures (Validation §§42–46 cover
  the improved scanners).
- `tests/engine_tests.py` — **Errors 0, Warnings 0**.
- `tests/regression_runner.py` — **PASS=10 WARNING=6 REGRESSION=0**.

---

## 5. What is NOT included / deferred to Phase 4
- Network-bound re-verification harnesses for DNS, TLS, and Open Ports.
- Live-signature regression for Technology Detection.
- Phase 4 does not begin until this report is reviewed and approved.