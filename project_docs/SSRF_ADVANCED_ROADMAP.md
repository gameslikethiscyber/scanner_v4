# Advanced SSRF Roadmap - Architecture & Design

Status: **Planned / future major release** (not implemented)
Baseline: `scanners/ssrf.py` (SOP Phase 3.3, v4.2.0) is the **stable release baseline**. The capabilities below are scheduled for a future major release after extensive real-world validation and benchmarking. This document is the architecture / design proposal.

Owner scanner: `SSRFScanner`
Scope guard: no new standalone scanners; improvements land inside the existing evidence-only `SSRFScanner` and its engine-facing evidence. No browser automation / no JS rendering / no login automation.

---

## 1. Goal

Turn SSRF from "detected yes/no" into a **classified, timeline-driven** finding set that distinguishes reachable attack surface (cloud metadata vs internal vs localhost/loopback), reports parser/encoding bypasses the app fails to block, and surfaces **blind** (out-of-band / timing) SSRF - always backed by reproducible evidence and dynamic confidence.

---

## 2. Proposed new techniques (added to scan())

Each new technique emits independent observations only after confirmation (2+ distinct payloads) unless explicitly noted. Cross-validation aggregates when 2+ different techniques agree on a parameter.

### 2.1 DNS Rebinding Detection
- **Concept**: send a hostname that resolves to an attacker IP on the first request (passes app-side SSRF filters) and to `127.0.0.1`/metadata on the second (consumed by the app's internal fetch) - the "two-provider" rebinding lookup.
- **Payload strategy**:
  - A controlled rebinding domain where the TTL flips between public and private (requires the scanner to run an `A` record server or subscribe to a rebinding service).
  - Self-hosted fallback: two records (`A -> scanner-public`, `A -> 127.0.0.1`) on the same name; evidence = response difference between the two resolutions that materially differs from baseline.
- **Confirmed only when**: the app's fetch resolves to both IPs and the observable response (content / error / timing) changes in a way consistent with an internal host; reproduced a second time (2 distinct payload domains or consecutive resolutions).
- **FP guard**: registration/ownership of the rebinding domain is attacker-controlled; a resolution flip alone is not proof - require a response distinguishable from the app's normal handling. Absent an OAST/self-host bind, mark as `possible`/indicative, never standalone.

### 2.2 Blind SSRF Indicators (no reflected content)
Detect via side-channels when the response body never reflects the fetch:

- **Delayed responses (time-based blind SSRF)**: measure per-payload baseline latency; payloads pointing to a slow/hanging internal host (e.g. a TCP endpoint that accepts-and-pauses) create a reproducible latency delta (>1.5-2 s beyond baseline, 2+ retries). Emit a `blind_timing` support observation.
- **Callback URLs / external interaction**: extend the existing out-of-band channel (`core/oast_manager`) so a blind HTTP/DNS interaction on an attacker-controlled domain confirms blind SSRF (`blind_oast`, verified evidence). The OAST path already exists in the scanner.
- **Time correlation**: timestamp request-send vs observed-interaction; require the interaction to fall within the scan's polling window and map to the exact payload subdomain (already how `check_interaction` matches).
- **FP guard**: timing deltas must exceed the app's own jitter (measure a 3-sample baseline stdev); external interaction is strong but requires the OAST manager to be available (never a hard failure when disabled).

Reproducibility for blind signals: re-fetch the payload URL and re-poll to confirm the interaction is not a one-off event.

### 2.3 URL Parser Confusion & Encoding Bypasses
Probe the app's URL parser with constructions that normalize differently server-side than the filter expects. Each bypass is a distinct payload family, reported separately (the exact bypass is actionable).

- `@` authority confusion: `http://allowed.com@127.0.0.1/`, `http://127.0.0.1#@allowed.com/`
- Trailing/embedded `#` and `/`: `http://127.0.0.1/..`, `http://127.0.0.1%2f`
- Double `//` (protocol-relative / scheme confusion): `//127.0.0.1/`, `http:/127.0.0.1/`, `http:\127.0.0.1\`
- Backslashes: `http:\\169.254.169.254\`
- Mixed/embedded encoding: URL-encode the host, double-encode `/`, percent-encode IP characters
- IPv6 forms: `[::1]`, `[0:0:0:0:0:ffff:127.0.0.1]`, `[::ffff:7f00:1]`
- Numeric IP representations: decimal (`2130706433`), octal (`0177.0.0.1`), hex (`0x7f000001`), and mixed-IP forms
- Scheme case / whitespace / plus variants

**Confirmed**: the bypassed target (internal/cloud) returns content/behavior distinct from a control request to a clearly external host, reproduced with a second bypass construction. Each recorded bypass carries `parser_variant` in evidence; a bypass that only changes the response but does not hit an internal/cloud target is **not** a finding by itself.

### 2.4 Advanced Protocol Abuse (gopher://, dict://, ftp://, file://)
- `file://` - local file disclosure: read `/etc/passwd`, `/proc/self/environ`, app source; confirmed by a distinct body containing known file markers (key-value `root:x:`, PHP open-tag, DB connection strings), reproduced on a second path.
- `gopher://` - request-smuggling style: encode a full HTTP request as a gopher payload to internal ports (e.g. Redis `info`/auth). Confirmed when an internal service returns a response that differs from baseline.
- `dict://` - protocol fingerprint: `dict://127.0.0.1:6379/info` yields a banner resembling a known service (Redis/Memcached). Confirmed when the banner is a known service version.
- `ftp://` - anonymous read to internal FTP; confirmed by directory/file listing markers.
- These reframe the existing `error_signature`/`internal_access` surface; emit a `protocol` variant observation with the exact scheme/target so the **same host reached by different schemes** is not deduplicated into one generic finding.

---

## 3. Fine-grained SSRF Risk Classification

Do not classify every SSRF equally. Each confirmed observation is classified by the reached target; the engine's severity/confidence input changes accordingly.

### 3.1 Classification model (`target_kind`)
- `loopback` - `127.0.0.0/8`, `[::1]`, `localhost` (own process)
- `private_net` - RFC1918 (`10/8`, `172.16/12`, `192.168/16`)
- `link_local` - `169.254/16`, `fe80::/10`
- `cloud_metadata` - `169.254.169.254`, `metadata.google.internal`, `100.100.100.200` (per provider: AWS/Azure/GCP/DO/OpenStack/Alibaba/Oracle)
- `public/offsite` - reachable external host (still SSRF if attacker-controlled)
- `file` / `gopher` / `dict` / `ftp` - protocol-based (no IP classification)

### 3.2 Risk weighting (feed into confidence/severity factors)
- `cloud_metadata` + `loopback` + `file` -> highest risk (credential / local-file disclosure)
- `private_net` / `link_local` -> high
- `offsite` attacker-controlled -> medium

### 3.3 FP guard
- Classification occurs only on confirmed technique observations (never a lone probe). `target_kind` is derived from the **resolved** target (after redirects), not the submitted string, so a parser bypass cannot mislabel.

---

## 4. Evidence Timeline

Change emission from a request/response snapshot to an ordered, auditable pipeline per observation:

```
Payload
  |  (observation.payload)
  v
HTTP Request        (method, URL, injected param, headers)
  v
Redirects           (ordered chain: 302/307 Location + status per hop)
  v
Final HTTP Response (status, headers, length, snippet, elapsed)
  v
Match -> technique/rule -> target_class -> deduced indicators
```

- Formalize the existing `_walk_server_chain` / `_emit_observation` data into a `timeline` member on each observation evidence where applicable:
  - `timeline.steps[]` - `{phase, url, status, location, size, elapsed}`
  - `timeline.redirects[]` - the ordered Location list from the chain walk
- The timeline is rendered in reports where the reporter exposes it (Markdown/HTML/TXT); JSON/CLI keep the raw structure.
- FP guard: the timeline must show the same payload -> request -> redirect -> response path for the confirmation payload too (reproducibility), so a one-off hop is not reported.

---

## 5. Evidence & Confidence integration

- Reuse `EvidenceBuilder` (`request_response`, `verified`, `likely`, `possible`, `cross-validation`), the CAP-* caps in the confidence engine, and `run_engine_pipeline`.
- Additive `evidence.raw_data` keys (backward-compatible): `technique`, `detection_method`, `target_kind`, `parser_variant`, `protocol`, `provider`, `timeline`, `confirm_payload`, `reproducible`.
- Confidence is derived (never static): number of observations, independent techniques per parameter, confirmed payload counts, verification passes, cross-validation. `target_kind` is a severity/correlation factor, not a standalone confidence.

---

## 6. False-Positive Rules (shared across new techniques)

1. **No reflection-only finding**: each technique requires a distinct observed signal (content, status, timing, OAST, protocol banner) reproduced with a second payload.
2. **No echoed-URL conflation**: an app that reflects the exact payload string back is excluded via the marker-not-in-URL guard (same principle as the metadata echo guard).
3. **No off-target follow**: SSRF probes never auto-follow app-emitted redirects, so the scanner client is not dragged to an internal/off-site host; internal host probes are bounded per parameter (no arbitrary port scans).
4. **Timing** deltas validated against measured baseline jitter; external-interaction requires the OAST manager configured (never a hard failure when disabled).

---

## 7. Benchmark + validation plan (per future phase)

Follow the established SOP before merging each capability:
- **Extend the local deterministic fixture** in `benchmarks/ssrf_benchmark.py`: a rebinding-ish target, a blind timing probe, parser-confusion endpoints, gopher/dict/file fixtures - plus clean controls (URL echo, generic 404, external-only redirect).
- **Metrics**: TP / FP / FN / TN / detection rate / avg scan time. Target >=95% detection rate; each new FP class explicitly documented (generic 5xx not internal, URL echo not metadata, etc.).
- **Validation section** (new section) in `test_validation.py` covering each technique's confirmed vs non-confirmed paths.
- **Gates**: `test_validation.py` 0/0, `tests.engine_tests` 0/0, `tests.regression_runner` REGRESSION=0.
- **External targets**: Juice Shop / DVWA / bWAPP / a reachable metadata-fetch lab and (for rebinding) a controlled rebinding domain, each to be reachable in the test environment.

---

## 8. Suggested sequencing (future release)

1. **Risk classification + evidence timeline** (structural, low blast radius) - foundation for everything below.
2. **Blind SSRF** (time + OAST correlation) - highest value, reuses the existing OAST path.
3. **URL parser confusion / encoding bypasses** - broadens coverage; each bypass is a distinct payload family.
4. **Advanced protocol abuse (file/gopher/dict/ftp)** - highest impact, most FP risk; needs the cleanest fixtures.
5. **DNS rebinding** - needs external bind/infrastructure; treat as an optional plugin mode.

Each step is independently benchmarkable; no single step blocks the others.

---

## 9. Non-goals (out of scope)

- Auto-exploitation (evidence-only; no file write to disk).
- Blind polling loops or TCP-connect port scanners (only payload-driven evidence).
- Browser / rendering / JS execution.