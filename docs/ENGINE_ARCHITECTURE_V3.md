# SEA Corporate Security Scanner — Engine Architecture v3.0

> **Status:** Draft for review. **Applies to:** engine (`core/`), scanners (`scanners/`),
> orchestrator (`main.py`), reports (`core/reporter.py`, `core/pdf_reporter.py`, `templates/`),
> and GUI consumption layer (`gui/services/`, `gui/controllers/`, `gui/widgets/summary.py`).
> **Approved by:** pending.

This document is the **single source of truth** for the v3.0 engine refactor. It replaces the
v2.x "compute everywhere" model with a pipeline of dedicated engines that produce one final
`Assessment` object consumed by every output interface (GUI, CLI, HTML, PDF, JSON).

---

## 1. High-Level Architecture

### 1.1 Design Principle

**Scanners collect evidence. Engines decide. Interfaces consume.**

- A scanner's only job is to probe the target and record **raw evidence** (`Evidence` objects),
  test counts, and technical fingerprints. It must **never** compute confidence, verification
  status, severity, CVSS, or risk.
- Every analytical decision is owned by exactly one engine. No engine reads another engine's
  internals — engines communicate through typed results (dataclasses / dicts defined in this doc).
- No output interface (GUI, CLI, HTML, PDF, JSON) may recompute a score. They render the
  `Assessment` model only.

### 1.2 Pipeline

```
                        ┌──────────────────────────────────────────────┐
                        │               Scan Pipeline                 │
                        │  main.py · gui/services/scan_worker.py      │
                        └──────────────────────────────────────────────┘
                                        │
                                        ▼
   ┌─────────────────┐        raw Evidence objects        ┌─────────────────┐
   │   Scanners      │ ──────────────────────────────────►│ Evidence Engine │
   │ (19 modules)    │      + test counts + fingerprints  │   normalization │
   └─────────────────┘                                    │   + scoring     │
                                                          └────────┬────────┘
                                                                   │ EvidenceScore /
                                                                   │ normalized Evidence
                                                                   ▼
   ┌──────────────────┐        per-finding confidence       ┌─────────────────┐
   │ Confidence Engine│ ◄───────────────────────────────────┤   (per finding) │
   │  0–100 + factors │                                      └─────────────────┘
   └────────┬─────────┘
            │ confidence + evidence levels
            ▼
   ┌──────────────────┐        verification classification ┌─────────────────┐
   │ Verification Eng │ ◄───────────────────────────────────┤   (per finding) │
   │ Confirmed/Likely/│    Confirmed·Likely·Possible·       │                 │
   │ Possible/Manual/ │    Manual Review·Unverified         │                 │
   │ Unverified       │                                     │                 │
   └────────┬─────────┘                                     └─────────────────┘
            │ severity (base + adjustments)
            ▼
   ┌──────────────────┐        CVSS + impact + exposure    ┌─────────────────┐
   │  Severity Engine │ ◄───────────────────────────────────┤   (per finding) │
   │  none→critical   │                                      │                 │
   └────────┬─────────┘                                      └─────────────────┘
            │ severity + confidence + verification
            ▼
   ┌──────────────────┐        risk score 0–100 + reasons  ┌─────────────────┐
   │    Risk Engine   │ ◄───────────────────────────────────┤  scan-wide      │
   └────────┬─────────┘                                     └─────────────────┘
            │ execution states (per finding)
            ▼
   ┌──────────────────┐        coverage % + quality +      ┌─────────────────┐
   │ Coverage Engine  │ ◄───────────────────────────────────┤  scan-wide      │
   └────────┬─────────┘      assessment-confidence impact  └─────────────────┘
            │
            ▼
   ┌──────────────────┐  one immutable Assessment object    ┌─────────────────┐
   │ Assessment Engine│ ────────────────────────────────────►│ Executive       │
   │  assembles model │      + statistics + metadata        │ Summary         │
   └────────┬─────────┘                                      │ Generator       │
            │                                                └────────┬────────┘
            ▼                                                        ▼
   ┌───────────────────────────────────────────────────────────────────────────┐
   │                            Report Engine                                 │
   │  core/reporter.py · core/pdf_reporter.py · templates/report.html.j2       │
   │  Consumes Assessment.to_dict() ONLY. Never recomputes.                    │
   └───────────────────────────────────────────────────────────────────────────┘
            │
            ▼
        GUI (SummaryView/RiskMeter) · CLI (Rich tables) · HTML · PDF · JSON
```

### 1.3 Module Map (v3)

| Module (new) | File | Replaces / Extracts from |
|---|---|---|
| Evidence Engine | `core/evidence_engine.py` | `core/evidence.py` (scoring only) |
| Confidence Engine | `core/confidence_engine.py` | archived `v2_apply_evidence_assessment()` (was `Finding._update_confidence_from_evidence()`) |
| Verification Engine | `core/verification_engine.py` (evolve) | archived `v2_apply_evidence_assessment()` (was `Finding._update_verification_status()`) |
| Severity Engine | `core/severity_engine.py` | `DecisionEngine._determine_severity/_assign_impact/_calculate_cvss` |
| Risk Engine | `core/risk_engine.py` | `RiskCalculator` |
| Coverage Engine | `core/coverage_engine.py` | `ScanResult.get_execution_states()/get_coverage()` |
| Assessment Engine | `core/assessment_engine.py` | `ScanResult.get_statistics()/get_overall_severity()` |
| Executive Summary Generator | `core/executive_summary.py` | inline strings in `get_statistics()` |
| Assessment Model | `core/assessment.py` | new — the single output contract |
| Metadata provider | `core/decision_engine.py` (reduce) | `DecisionEngine.STANDARDS/RECOMMENDATIONS` kept as static metadata |

---

## 2. Assessment Model

`core/assessment.py` defines the **only** object that leaves the engine core for presentation.
It is immutable after construction; all fields are populated by the Assessment Engine.

```python
@dataclass(frozen=True)
class Assessment:
    scan_id: str
    target: str
    target_host: str
    start_time: str            # ISO-8601
    end_time: str
    duration_seconds: float

    # --- Overall risk verdict ---
    overall_score: int         # 0–100 (Risk Engine output)
    overall_severity: str      # none | info | low | medium | high | critical
    overall_tier: str          # none | low | elevated | high | critical
    overall_label: str         # human label e.g. "Elevated Risk"
    overall_description: str
    overall_color: str         # hex
    overall_reasons: list[str] # why this verdict

    # --- Assessment confidence ---
    assessment_confidence: int          # 0–100
    assessment_confidence_factors: dict[str, int]
    assessment_confidence_explanation: str

    # --- Coverage ---
    coverage: "CoverageReport"          # dataclass, see §6.4

    # --- Narrative ---
    summary: "ExecutiveSummary"         # dataclass, see §2.2

    # --- Content ---
    findings: list["FindingAssessment"] # one assessed entry per module
    modules: dict[str, dict]            # per-module rollup (state, severity, confidence, verification)
    statistics: dict                    # backward-compatible stats dict (v2.x shape, §8)
    metadata: dict                      # versions, config snapshot, auth, crawler diag

    def to_dict(self) -> dict: ...
    def to_json(self) -> str: ...       # used by CLI JSON export + GUI HistoryStore
```

### 2.1 FindingAssessment (assessed finding)

Derived per module from `Finding` + engine outputs. Kept separate from the raw `Finding` so
scanners never need to know about assessment fields.

```python
@dataclass(frozen=True)
class FindingAssessment:
    module: str
    title: str
    status: str               # pass|fail|warning|info|skipped|unknown
    execution_state: str      # passed|failed|warning|info|skipped|not_applicable
    execution_reason: str
    severity: str             # none|info|low|medium|high|critical
    confidence: int
    confidence_factors: dict[str, int]
    confidence_explanation: str
    verification: str         # confirmed|likely|possible|manual_review|unverified
    evidence_quality: int     # 0–100 from Evidence Engine
    cvss_score: float
    cvss_vector: str
    cvss_explanation: str
    exploitability: str       # easy|medium|hard|theoretical|unknown
    impact: dict[str, int]    # {confidentiality, integrity, availability}
    cwe_id: str
    owasp_category: str
    capec_id: str
    mitre_id: str
    asvs_reference: str
    evidence: list[dict]      # rendered Evidence.to_dict()
    recommendations: list[dict]
    references: list[str]
    risk_contribution: float  # from Risk Engine
    timestamps: dict[str, str]  # {created, updated}
```

### 2.2 ExecutiveSummary

```python
@dataclass(frozen=True)
class ExecutiveSummary:
    prose: str                     # natural-language paragraph(s)
    key_findings: list[str]        # bullet list of the decisive issues
    positive_highlights: list[str] # what passed / is configured well
    coverage_statement: str
    action_priority: list[str]     # ordered remediation priorities
    verified_count: int
    likely_count: int
    requires_review_count: int
```

### 2.3 CoverageReport

```python
@dataclass(frozen=True)
class CoverageReport:
    total: int
    executed: int
    passed: int
    failed: int
    warning: int
    info: int
    skipped: int
    not_applicable: int
    coverage_percent: int
    coverage_quality: int        # 0–100, penalised by skipped/failed/na
    execution_states: dict       # counts + per-module details (v2 shape preserved)
    skip_reasons: dict[str, list[str]]
    explanation: str
    assessment_confidence_impact: int   # delta applied to assessment_confidence
```

---

## 3. Finding Model

`core/finding.py` keeps `Finding` as the **raw scanner output record** plus the standardised
enum set. During v3 the `Finding` gains a **strict contract** enforced by the Evidence Engine
gateway: scanners populate the `evidence` fields below and set status only to
`SKIPPED | PASS`* provisional* outcomes; all assessment fields are written exclusively by engines.

### 3.1 Scanner-populated fields (raw output)

```python
module: str
title: str
description: str
target: str
status: Status            # SKIPPED (explicit skip) | PASS-provisional | UNKNOWN (deferred)
                          #  — engine overrides FAIL/WARNING/INFO/PASS verdicts
evidence: list[Evidence]  # raw evidence only; no confidence math here
tests_performed: int
tests_run: int
tests_passed: int
payload_evidence: list[str]
fingerprint: dict         # technologies, database, headers, etc.
skip_reason: str
reason: str               # scanner-side observation text (engine may refine)
recommendation: str       # engine fills from STANDARDS if empty
duration: float
scan_errors: int
detection_methods: list[str]
timestamp: str
```

### 3.2 Engine-populated fields (assessment)

Written only by the pipeline (Confidence → Verification → Severity), never by scanners:

```python
confidence: int                 # Confidence Engine
confidence_factors: dict        # Confidence Engine
confidence_explanation: str     # Confidence Engine
verification_status: str        # Verification Engine
evidence_quality: int           # Evidence Engine
severity: Severity              # Severity Engine
exploitability: Exploitability  # Severity Engine
impact: dict                    # Severity Engine
cvss_score: float               # Severity Engine
cvss_vector: str                # Severity Engine
cvss_explanation: str           # Severity Engine
cwe_id / owasp_category / capec_id / mitre_id / asvs_reference  # metadata provider
execution_state: ExecutionState # Coverage Engine (classify_execution_state — single owner)
state_reason: str               # Coverage Engine
matched_rules: list[str]        # Evidence/Confidence Engines
correlation_escalated: bool     # Confidence/Severity Engines (from CorrelationEngine output)
correlation_findings: list[str] # CorrelationEngine output
cross_validated: bool           # Confidence Engine (from verification passes)
verification_passes: int        # Confidence Engine
```

### 3.3 Enum contract (unchanged, standardised)

| Enum | Values |
|---|---|
| `Status` | pass · fail · warning · unknown · skipped · safe · vulnerable · error · info |
| `Severity` | none · info · low · medium · high · critical |
| `Exploitability` | easy · medium · hard · theoretical · unknown |
| `ExecutionState` | passed · failed · skipped · not_applicable · warning · info · auth_required · authenticated · public_only · session_expired · login_failed · token_invalid |
| `EvidenceLevel` | verified · exploited · confirmed · likely · possible · unknown · not_tested |

Verification labels (report vocabulary): `verified · likely · possible · manual_review · unverified`
(see `VERIFICATION_LABELS`).

---

## 4. Evidence Model

`core/evidence.py` is unchanged in shape and becomes the **reusable evidence contract**.
The Evidence Engine adds scoring on top; it never changes the data model.

```python
@dataclass
class Evidence:
    level: EvidenceLevel       # verified|exploited|confirmed|likely|possible|unknown|not_tested
    type: EvidenceType         # payload_reflection|execution|error_message|timing_delay|
                               # header_missing|header_weak|configuration|behavioral|fingerprint|
                               # response_analysis|request_response|behavior_change|dom_change|
                               # content_reflection|server_behavior|cross_validation|
                               # consistency_check|correlation
    description: str
    payload: str | None
    endpoint: str | None
    parameter: str | None
    method: str = "GET"
    timestamp: str
    raw_data: dict             # snippet/headers/timing/request/response (redacted by SecretRedactor)
    confidence_bonus: int      # from EvidenceBuilder presets (see §6.2)
    weight: int                # from EvidenceBuilder presets
    verification_pass: int     # pass index when produced by VerificationEngine
    verification_method: str
```

### 4.1 EvidenceBuilder presets (reference)

| Builder method | level | bonus | weight |
|---|---|---|---|
| `exploited()` | exploited | +35 | 5 |
| `verified()` / `cross_validation()` | verified | +25 | 5 |
| `request_response()` | confirmed | +25 | 5 |
| `confirmed()` / `behavior_change()` / `dom_change()` / `content_reflection()` | confirmed | +20 | 4 |
| `likely()` / `server_behavior()` / `consistency_check()` | likely | +10 | 3 |
| `possible()` | possible | +5 | 2 |
| `unknown()` | unknown | 0 | 1 |
| `not_tested()` | not_tested | 0 | 0 |
| `error()` | unknown | −20 | 0 |

---

## 5. Engine Responsibilities

Each engine is a pure, stateless (or trivially stateful) class. No engine imports another
engine; each consumes typed inputs and returns typed outputs.

### 5.1 Evidence Engine — `core/evidence_engine.py`

- **Inputs:** `list[Evidence]` (raw), optional correlation evidence from `CorrelationEngine`.
- **Responsibilities:**
  1. Normalise evidence (coerce dicts/objects → `Evidence`).
  2. Score evidence quality: `evidence_quality` 0–100 from level, type, payload presence,
     raw_data completeness (snippet/headers/timing), verification passes.
  3. Detect contradictory / error evidence and mark a negative contribution.
  4. Detect cross-validation / correlation evidence markers.
  5. Emit `EvidenceScore` (below) consumed by the Confidence Engine.
- **Outputs:** `EvidenceScore { evidence_quality: int, weighted_bonus: int, total_weight: int,
  verification_passes: set[int], has_cross_validation: bool, has_error: bool,
  strongest_level: str, factors: dict }`.

### 5.2 Confidence Engine — `core/confidence_engine.py`

- **Inputs:** `EvidenceScore`, plus correlation boosts (from `CorrelationEngine`).
- **Responsibilities:**
  1. Compute `confidence` 0–100 per finding.
  2. Produce `confidence_factors` (auditable name → delta) and `confidence_explanation`.
  3. Cap confidence by strongest evidence level (exploited=100, verified=90, confirmed=85,
     likely=75, possible=60; error caps at 40).
  4. Apply correlation / cross-validation boosts.
- **Outputs:** `ConfidenceResult { confidence: int, factors: dict, explanation: str,
  verification_passes: int, cross_validated: bool }`.

### 5.3 Verification Engine — `core/verification_engine.py`

- **Inputs:** `ConfidenceResult`, evidence levels, `VerificationPass` results from scanner
  multi-pass tests.
- **Responsibilities:**
  1. Derive verification classification from the dynamic confidence bands (§6.3).
  2. Allow hard overrides: exploited/verified evidence → `confirmed`; error evidence → `unverified`.
  3. Retain `verify_with_retry()` / `run_multi_pass()` HTTP verification (unchanged).
- **Outputs:** `VerificationResult_ { status: str, label: str, explanation: str }` per finding.

### 5.4 Severity Engine — `core/severity_engine.py`

- **Inputs:** raw finding (status, module), `ConfidenceResult`, `VerificationResult_`, metadata
  from the standards provider (`DecisionEngine.STANDARDS`).
- **Responsibilities:**
  1. Map module → base severity from standards metadata (SQLi=critical, XSS=high, …).
  2. Apply adjustments: unverified critical → high; verified high → high; correlation
     `severity_escalation`; severity never decreases below base for a FAIL finding.
  3. Assign exploitability, impact (CIA multipliers), CVSS score + vector + explanation.
- **Outputs:** `SeverityResult { severity, exploitability, impact, cvss_score, cvss_vector,
  cvss_explanation, cwe_id, owasp_category, capec_id, mitre_id, asvs_reference }`.

### 5.5 Risk Engine — `core/risk_engine.py`

- **Inputs:** per-finding severity, confidence, verification, occurrences; correlation
  `risk_multiplier`.
- **Responsibilities:**
  1. Compute the weighted risk score 0–100 (§6.1).
  2. Produce per-finding `risk_contribution` and a human `explanation` list.
  3. Apply correlation multipliers and escalation.
  4. Emit the security letter grade.
- **Outputs:** `RiskResult { risk_score: int, security_grade: str, total_weighted: float,
  max_possible: float, breakdown: list[dict], explanation: list[str], summary: str,
  calculation_formula: str }`.

### 5.6 Coverage Engine — `core/coverage_engine.py`

- **Inputs:** all findings (execution states), `total_modules`.
- **Responsibilities:**
  1. Classify each finding → `ExecutionState` (single owner; archived `v2_compute_execution_state` diverged on UNKNOWN findings).
  2. Compute executed/skipped/failed/na counts and `coverage_percent`.
  3. Compute `coverage_quality` (0–100) and the delta applied to `assessment_confidence`.
  4. Build skip/na reason groupings and explanatory prose.
- **Outputs:** `CoverageReport` (§2.3).

### 5.7 Assessment Engine — `core/assessment_engine.py`

- **Inputs:** all engine outputs + `ScanResult`/raw findings + scan metadata.
- **Responsibilities:**
  1. Assemble the immutable `Assessment` object.
  2. Compute overall severity verdict + reasons (multi-factor policy from
     `ScanResult.get_overall_severity()`, moved here).
  3. Compute `assessment_confidence` (§6.5).
  4. Build `statistics` dict in the exact v2.x shape (§8) so reports/GUI keep working.
- **Outputs:** `Assessment`.

### 5.8 Executive Summary Generator — `core/executive_summary.py`

- **Inputs:** `CoverageReport`, `RiskResult`, overall verdict, verified/likely/review counts,
  module rollups.
- **Responsibilities:** produce `ExecutiveSummary` prose and priorities. No scoring; pure text.
- **Outputs:** `ExecutiveSummary` (§2.2).

### 5.9 Correlation Engine — `core/correlation_engine.py`

- **Change of role:** no longer mutates `Finding.confidence`/`Finding.severity` in place.
  It returns `CorrelationResult`-derived **boost payloads** (`confidence_boost`,
  `severity_escalation`, `risk_multiplier`) that the Confidence, Severity, and Risk engines apply.
- **Outputs:** `list[CorrelationResult]` + `get_correlation_summary()` (shape preserved).

---

## 6. Scoring Formula

No value in this document is arbitrary; each formula has a stated rationale. All numbers are
declared as constants at the top of the owning engine for auditability.

### 6.1 Risk Score (Risk Engine)

```
For each FAIL/VULNERABLE finding f:
    sev_weight(f)     = {critical:10, high:7, medium:5, low:3, info:1, none:0}
    confidence_factor = f.confidence / 100
    verif_mult(f)     = {confirmed:1.0, likely:0.85, possible:0.6,
                         manual_review:0.4, unverified:0.3}
    occ_factor(f)     = min(f.occurrences, 5) / 5
    contribution(f)   = sev_weight × confidence_factor × verif_mult × (0.8 + 0.2·occ_factor)
    max_possible     += sev_weight

For each WARNING finding w:
    sev_weight(w)     = (base weight) × 0.5
    max_possible     += sev_weight(w) × 2
    contribution(w)   = sev_weight(w) × confidence_factor × verif_mult × (0.8 + 0.2·occ_factor)

risk_score = 100 × Σ contribution / Σ max_possible          # rounded to 0.1
```

Correlation multiplier (if rule fires): `contribution(f) ×= rule.risk_multiplier`
(clamped: total never exceeds max_possible).

**Rationale:** score reflects both impact and certainty; unverified/low-confidence findings
contribute less, so risk is not inflated by unconfirmed noise. Correlations raise risk only
when the combined attack surface is genuinely larger.

Grade bands: A+ ≤5 · A ≤10 · B+ ≤20 · B ≤30 · C+ ≤40 · C ≤50 · D+ ≤65 · D ≤80 · F >80.

### 6.2 Confidence (Confidence Engine)

```
base = Σ(evidence.confidence_bonus × evidence.weight) / Σ(evidence.weight) + 50
       # when no weighted bonus present: base = 50
Adjustments (additive, each recorded in confidence_factors):
    +5   evidence count ≥ 2 and no error evidence          ("Multiple Evidences")
    +5   one verification pass                             ("Verification pass")
    +10  ≥2 distinct verification passes                   ("Multi-pass verification")
    +10  cross-validation evidence present                 ("Cross-validation")
    +5   correlation boost applied                         ("Correlation boost")
    +5   cross_validated flag                              ("Cross-validated")
    −10  error evidence present (hard cap 40)              ("Error detected")
Cap by strongest evidence level (max_confidence):
    exploited→100 · verified→90 · confirmed→85 · likely→75 · possible→60 · else 50
confidence = clamp(0, max_confidence, base)
```

**Rationale:** confidence is anchored at 50 (uncertain) and moved by weighted evidence strength,
verification redundancy, and independent cross-validation; the level cap prevents a single weak
hint from producing high confidence.

### 6.3 Verification (Verification Engine) — dynamic thresholds

```
Verification classification from confidence bands:
    confirmed      confidence ≥ 95
    likely         confidence 80–94
    possible       confidence 55–79
    manual_review  confidence 35–54
    unverified     confidence < 35
Hard overrides (evidence-based, applied before bands):
    any exploited/verified evidence          → confirmed
    error evidence present                   → unverified
    no evidence at all                       → unverified
```

**Rationale (SOP v3):** verification must scale with collected evidence strength. A finding
reaching ≥95 confidence (exploited/verified evidence, multi-pass confirmation, cross-validation)
is `confirmed`; 80–94 is `likely`; 55–79 `possible`; 35–54 needs a human (`manual_review`);
below 35 is `unverified`.

### 6.4 Coverage (Coverage Engine)

```
executed   = passed + failed + warning + info
coverage_percent = 100 × executed / total          # total = max(total_modules, len(findings))
coverage_quality = 100 × executed / total
                   − 15 × (failed / total)         # failed modules count hard
                   − 8  × (skipped / total)        # skipped modules reduce trust
                   − 4  × (not_applicable / total) # NA is acceptable but noted
                   (clamped to 0–100)
assessment_confidence_impact = −round((100 − coverage_quality) / 5)
```

**Rationale:** a scan that skipped half its modules cannot assert the same confidence as a full
scan; failures are worse than skips, and NA (legitimately inapplicable) is a minor note.

### 6.5 Assessment Confidence (Assessment Engine)

```
assessment_confidence = 100
    − 6 × (skipped_count > 0)                    # each skipped module group
    − 10 × (failed_count > 0)                    # each failed module
    − max(0, 30 − coverage_quality) × 0.5        # degraded coverage
    + 5  × (verified_vulns > 0)                  # hard evidence raises certainty
    − 10 × (unverified vulns present)            # unresolved findings lower certainty
    (clamped to 0–100)
```

Each term recorded in `assessment_confidence_factors` with a one-line explanation.

### 6.6 Severity (Severity Engine)

```
Base severity per module from standards metadata (DecisionEngine.STANDARDS):
    SQL Injection=SSTI: critical · XSS, SSRF, Host Header, LFI: high
    Open Redirect, CSRF, CORS, HTTP Methods, Sensitive Files, Headers, TLS, Open Ports: medium
    Cookies, DNS, Security.txt, Source Leaks: low · Tech Detection: none

FAIL finding → base severity (never lower).
WARNING finding → base severity (reported as warning, not FAIL).
Adjustments:
    critical with no verified/likely evidence     → reported high      (unverified critical)
    correlation severity_escalation               → raise if higher     (e.g. xss+csp → critical)
Impact CIA:
    impact_axis = base_impact_axis × multiplier   (critical 1.0 · high 0.8 · medium 0.6 · low 0.4 · else 0.2)
    min 1 per axis.
CVSS:
    base_score = {none:0, info:1.0, low:3.0, medium:5.0, high:7.0, critical:9.0}
    cvss_score = min(10, base_score + (confidence/100) × 0.5)   # rounded 0.1
    vector per severity defaults: CRITICAL AV:N/AC:L/PR:N/UI:N, HIGH AV:N/AC:L/PR:L/UI:N,
    MEDIUM AV:N/AC:L/PR:L/UI:R, LOW AV:A/AC:H/PR:H/UI:R, C/I/A from impact thresholds (≥4 H, ≥2 L).
```

**Rationale:** severity stays grounded in a curated per-technique baseline (standard mapping),
then reflects certainty (CVSS boost), exploitability class, and real correlation escalation —
never raw guesswork.

---

## 7. Data Flow (scanner result → report)

**Since A9 there is exactly one assessment lifecycle per scan.** Every production
orchestrator (`main.py` `SeaScanner.run()`, GUI `ScanWorker`, backend
`scan_runner`) calls `scan_result.assess()` (→ idempotent
`run_assessment_pipeline`) **once**, then all consumers read that one immutable
`Assessment`. No component performs its own risk/severity/confidence/coverage
computation.

1. **Orchestrator** (`main.py` `SeaScanner.run()` or GUI `ScanWorker`) drives:
   auth probe → crawl → host/page scanner runs → engine pipeline → assessment.
2. Each `BaseScanner.run()` executes `scan()` collecting evidence, then calls the
   **engine pipeline entry point** (`run_engine_pipeline`; the only execution
   path since A8.9):
   `evidence_score → confidence → verification → severity` and attaches results to the `Finding`.
3. Orchestrator adds all findings to `ScanResult` (dedup/merge unchanged), records crawler diag,
   auth stats, request counts.
4. Orchestrator calls **`scan_result.assess()`** → `run_assessment_pipeline` runs the
   single lifecycle in order:
   `CorrelationEngine` boost payloads (no in-place mutation) → `RiskEngine` → `CoverageEngine`
   → `AssessmentEngine` → `ExecutiveSummary` → builds the immutable `Assessment` and stores it
   on `scan_result.assessment`. The pipeline is **idempotent**: a second call returns the
   already-built `Assessment` (correlation is never applied twice).
5. `Assessment.to_dict()` produces the v2.x-compatible `statistics` dict (§8).
6. **Report Engine** (`Reporter`/`pdf_reporter`) renders `Assessment.statistics` + `Assessment.findings`
   into HTML (Jinja2 template or inline fallback), JSON, Markdown, CSV, TXT, PDF — via the
   `_stats(scan_result)` helper, which reads the stored `Assessment` first.
7. **GUI** (`SummaryView`, `RiskMeter`, History detail) and **CLI** (`show_summary`) render the
   same `Assessment.to_dict()` output. History persists `overall_tier` from the Assessment.
8. **Backend** (`scan_runner`) converts OAST interactions into `EvidenceBuilder().exploited(...)`
   evidence inside the scan, then calls `assess()` and reads `assessment.statistics`
   (risk/tier/correlations_found) — the OAIST confirmation is an engine hook, not a field override.

**Legacy fallback (un-assessed results only):** `ScanResult.get_statistics()`/`get_coverage()`/
`get_overall_severity()`/`calculate_dynamic_risk_score()`/`calculate_risk_breakdown()`/`run_correlation()`
delegate to the stored `Assessment` when one exists and fall back to inline engines only for raw,
un-assessed results (used by `test_validation.py` and the regression harness). Production paths
never exercise the fallback.

---

## 8. Backward Compatibility

**Goal:** existing scanners keep working unchanged during migration; every report format and the
GUI keep functioning at every intermediate commit. **As of A8.9 the migration window is closed** —
there is one execution path (`run_engine_pipeline`), and the v2 logic lives only in
`tests/v2_reference.py`.

1. **Scanner API stable.** `BaseScanner.scan()`, `run()`, `inject_payload`,
   `add_evidence_with_snippet`, `capture_http_evidence`, etc. are unchanged signatures.
   Legacy helpers (`create_safe_finding`, `create_vulnerable_finding`, `verify_multi_pass`,
   `add_verification_evidence`, `capture_response_analysis`) were removed in A8.9 — scanners emit
   evidence only and call the pipeline via `run()`.
2. **Legacy facade removed (A8.9).** `DecisionEngine.decide(finding)` no longer exists in
   production; it is archived as `tests.v2_reference.v2_decide` / `V2DecisionEngine` and is used
   only by the regression harness (`tests/engine_paths.run_v2`).
3. **`statistics` dict shape preserved.** `Assessment.statistics` reproduces every key of
   `ScanResult.get_statistics()` (risk_score, overall_*, coverage_*, executive_summary,
   risk_breakdown, execution_states, auth, versions, …). `Reporter`, `pdf_reporter`, Jinja2
   template, and GUI `SummaryView` keep rendering without modification.
4. **`Finding.to_dict()` / `Evidence.to_dict()` unchanged.** JSON exports, HistoryStore entries,
   and saved reports remain readable.
5. **`ScanResult.get_statistics()`/`get_coverage()`/`get_overall_severity()`/`validate()`**
   retained as **delegations to the stored `Assessment`** (present since A9; inline engine
   fallback only for un-assessed results). Production consumers (`Reporter`, `pdf_reporter`,
   GUI, CLI, backend) always read Assessment data. The delegation methods are deprecated and
   removed at A10 once consumers call the `Assessment` directly.
6. **Strict validation flag honoured.** `Reporter(strict_validation=...)` behaviour preserved;
   the known "Skipped count does not match skipped findings" quirk is addressed in Phase B1 by
   aligning Coverage Engine counting with `get_skipped_findings()`.
7. **Config compatibility.** `ScanConfig` gains new optional fields with defaults; no existing
   field renamed or removed.

---

## 9. Extension Model

Adding a scanner or a new finding type must **not** require editing any engine.

### 9.1 New scanner (e.g. IDOR, XXE, Deserialization)

1. Create `scanners/<name>.py` extending `BaseScanner` (implement `scan()` collecting evidence).
2. Register in `scanners/registry.py` (import + one list entry + `_SCANNER_NAME_MAP`).
3. Add standards metadata entry to `DecisionEngine.STANDARDS`:
   `{cwe, owasp, capec, mitre, asvs, severity, impact}` (single dictionary entry).
4. Done — engines pick it up via the standards provider and module-based mapping.

### 9.2 New evidence type / level

Add to `EvidenceType`/`EvidenceLevel` enums + optional `EvidenceBuilder` preset. The Evidence
Engine's scoring tables reference levels generically; no engine logic change required unless a
new *kind* of evidence (e.g. a new hard-cap level) is introduced — then the cap table in the
Confidence Engine is the single place to touch.

### 9.3 New correlation rule

Append a `CorrelationRule` to `CorrelationEngine.RULES` (module set, boosts, escalation,
multiplier). No engine change.

### 9.4 Engine interface contract for extensions

- Engines consume only the public contracts in this document (§2, §3, §4, §5).
- Engines never import scanners; scanners never import engines.
- All numeric policies are module-level constants, documented in §6.

---

## 10. Public Interfaces

No component may reach into another component's internals. The only legal imports:

| Consumer | May import | Must not |
|---|---|---|
| `scanners/*` | `core/finding` (Finding, Status, Severity enums), `core/evidence` (Evidence, EvidenceBuilder, EvidenceLevel), `core/response_analyzer`, `core/payload_mutator`, `core/utils`, `core/http_client` | compute confidence/verification/severity/CVSS/risk; set `finding.severity`/`finding.confidence`/`finding.verification_status` directly |
| `core/evidence_engine` | `core/evidence` | — |
| `core/confidence_engine` | `core/evidence`, `EvidenceScore` | read `Finding` internals beyond public fields |
| `core/verification_engine` | `core/evidence`, `core/response_analyzer` | — |
| `core/severity_engine` | `core/finding`, standards metadata | risk/coverage logic |
| `core/risk_engine` | `core/finding` | severity assignment |
| `core/coverage_engine` | `core/finding` | risk/severity logic |
| `core/assessment_engine` | all engine outputs, `core/finding` | recompute scores |
| `core/executive_summary` | `CoverageReport`, `RiskResult`, verdict | recompute scores |
| `core/reporter` / `core/pdf_reporter` / templates | `Assessment.to_dict()`, `FindingAssessment` | recompute scores |
| `gui/*` | `Assessment.to_dict()`, `ScanResult` (via worker) | recompute scores |
| `main.py` | everything via public entry points | — |

Entry-point signatures:

```python
# Evidence Engine
EvidenceEngine().score(evidence: list[Evidence]) -> EvidenceScore

# Confidence Engine
ConfidenceEngine().compute(evidence_score: EvidenceScore,
                           correlation_boost: int = 0,
                           cross_validated: bool = False) -> ConfidenceResult

# Verification Engine
VerificationEngine().classify(confidence: int,
                              evidence_levels: list[str],
                              has_error: bool) -> VerificationResult_
VerificationEngine().verify_with_retry(...)         # unchanged (HTTP)
VerificationEngine().run_multi_pass(...)            # unchanged (HTTP)

# Severity Engine
SeverityEngine().assess(finding, confidence: ConfidenceResult,
                        verification: VerificationResult_,
                        correlation_escalation: str | None = None) -> SeverityResult

# Risk Engine
RiskEngine().calculate(findings) -> RiskResult

# Coverage Engine
CoverageEngine().report(findings, total_modules: int) -> CoverageReport

# Assessment Engine
AssessmentEngine().build(scan_result, coverage: CoverageReport,
                         risk: RiskResult, metadata: dict) -> Assessment

# Executive Summary Generator
ExecutiveSummaryGenerator().generate(assessment_parts) -> ExecutiveSummary
```

---

## 11. Migration Plan (v2.x → v3)

Sequenced so the codebase is green at every step. **UI is intentionally not redesigned**
during Phases A1–A10.

### Phase A1 — Evidence Engine + Assessment shell
| File | Change | Why |
|---|---|---|
| `core/evidence_engine.py` | **NEW** — `EvidenceScore`, scoring | normalise + score raw evidence |
| `core/assessment.py` | **NEW** — Assessment/FindingAssessment/ExecutiveSummary/CoverageReport dataclasses | the v3 output contract |
| `core/evidence.py` | unchanged | data model reused as-is |
| Impact | Low — additive, nothing calls it yet | |

### Phase A2 — Confidence Engine
| File | Change | Why |
|---|---|---|
| `core/confidence_engine.py` | **NEW** — move `_update_confidence_from_evidence()` logic here | single owner of confidence |
| `core/finding.py` | `add_evidence()` stops recomputing; delegates to ConfidenceEngine (compat: keep computing when engine absent) — **compat removed in A8.9**, `add_evidence` is a plain append | remove logic from model |
| Impact | Medium — confidence values must match old behaviour (regression check) | |

### Phase A3 — Verification Engine
| File | Change | Why |
|---|---|---|
| `core/verification_engine.py` | add `classify()` dynamic-band logic + hard overrides | §6.3 |
| `core/finding.py` | `_update_verification_status()` delegates to `classify()` — **removed in A8.9**, archived as `v2_apply_evidence_assessment` | single owner |
| Impact | Low–Medium — statuses may shift slightly; validated in Phase B2 | |

### Phase A4 — Severity Engine
| File | Change | Why |
|---|---|---|
| `core/severity_engine.py` | **NEW** — extract `_determine_severity/_determine_exploitability/_assign_impact/_calculate_cvss` | single owner |
| `core/decision_engine.py` | keep `STANDARDS/RECOMMENDATIONS/CVSS_DESCRIPTIONS`; `decide()` becomes facade delegating to new engines — **facade removed in A8.9**, archived as `tests/v2_reference.v2_decide` | metadata provider + compat |
| Impact | Medium | |

### Phase A5 — Risk Engine
| File | Change | Why |
|---|---|---|
| `core/risk_engine.py` | **NEW** — move `RiskCalculator`, add correlation multipliers | single owner |
| `core/decision_engine.py` | `RiskCalculator` delegates / removed | — |
| Impact | Low — formula identical; tests compare old vs new score | |

### Phase A6 — Coverage Engine
| File | Change | Why |
|---|---|---|
| `core/coverage_engine.py` | **NEW** — move `get_execution_states()/get_coverage()`, add quality + confidence impact | §6.4 |
| `core/finding.py` | `ScanResult.get_coverage()` delegates | fix skipped-count reconcile |
| Impact | Medium — addresses the strict-validation quirk | |

### Phase A7 — Assessment Engine + Executive Summary
| File | Change | Why |
|---|---|---|
| `core/assessment_engine.py` | **NEW** — assemble Assessment, overall verdict, assessment_confidence, statistics dict | §2, §6.5 |
| `core/executive_summary.py` | **NEW** — extract narrative builder from `get_statistics()` | §5.8 |
| `core/finding.py` | `ScanResult.get_statistics()/get_overall_severity()` delegate to Assessment Engine | single owner |
| Impact | Medium — statistics shape must remain byte-compatible with v2 | |

### Phase A8 — Scanner evidence-only enforcement
| File | Change | Why |
|---|---|---|
| `scanners/base.py` | `run()` calls the pipeline entry point (`run_engine_pipeline`); all legacy compat layers removed (A8.9) | enforce evidence-only |
| `scanners/*.py` (19) | remove direct `status/severity/confidence/verification_status` assignment; emit evidence + provisional status only | core SOP requirement |
| `core/correlation_engine.py` | stop mutating findings; return boost payloads | data ownership |
| Impact | High — largest diff; mitigated because engine outputs must reproduce v2 behaviour (Phase B2 comparison) | |

### Phase A9 — Pipeline wiring — **COMPLETED**
| File | Change | Why |
|---|---|---|
| `core/pipeline.py` | `run_assessment_pipeline` **idempotent**: builds and stores `scan_result.assessment` (returns existing on re-call) | one Assessment per scan; correlation applied once |
| `core/finding.py` | `ScanResult.assess(**kwargs)` gateway; `self.assessment`; legacy stats/risk/severity/coverage/correlation methods **delegate to the stored Assessment** (inline fallback only for un-assessed results) | single source of truth for CLI/GUI/backend |
| `main.py` | `run()` calls `self.scan_result.assess()`; `run_scan_on_all_pages()` no longer calls `run_correlation()`; summary/reports consume the Assessment | single source of truth for CLI |
| `gui/services/scan_worker.py` | worker calls `scan_result.assess()`; `_build_summary` reads `assessment.assessment_confidence`; history persists `overall_tier` | single source of truth for GUI |
| `gui/main_window.py` / `gui/pages/history_page.py` | persist/read `overall_tier` from Assessment-derived summary | History reflects Assessment verdict |
| `backend/app/scan_runner.py` | OAIST confirmation → `EvidenceBuilder().exploited(...)` evidence hook; final phase = `assess()` + `assessment.statistics` (no manual correlation/statistics) | backend consumes the same Assessment |
| `core/reporter.py` / `core/pdf_reporter.py` | `_stats(scan_result)` helper reads the stored Assessment first; render via `Assessment.to_dict()` | never recompute |
| Impact | Medium — GUI layout unchanged, data source swapped to the immutable Assessment | |

### Phase A10 — Report Engine consumption
| File | Change | Why |
|---|---|---|
| `core/reporter.py` | `generate_*` consume the `Assessment` directly (drop `ScanResult` delegation methods) | never recompute |
| `core/finding.py` | remove delegation methods (`get_statistics`/`get_coverage`/`get_overall_severity`/`calculate_dynamic_risk_score`/`calculate_risk_breakdown`/`run_correlation`), `RiskCalculator`, mutating `CorrelationEngine.correlate()` | A9 consumers already read the Assessment |
| `core/pdf_reporter.py` | same | — |
| `templates/report.html.j2` | extend with assessment_confidence / coverage_quality fields (optional) | new v3 narrative fields |
| Impact | Low–Medium | |

### Phase B — Validation & rollback decision
1. Run `test_validation.py` (0 errors) + new per-engine unit tests.
2. Live scan comparison (old vs new scores) across the 19 modules; diff risk/severity/verification.
3. Fix divergences; if any engine output cannot reproduce v2 behaviour, that engine is revised
   before Phase A8/A9 land.
4. Verify GUI offscreen launch + CLI report generation; update `PROJECT_STATE.md`.

### Net impact estimate
- **New files:** `core/{evidence_engine,confidence_engine,severity_engine,risk_engine,coverage_engine,assessment_engine,assessment,executive_summary}.py` (8).
- **Modified:** `core/finding.py`, `core/decision_engine.py`, `core/verification_engine.py`, `core/correlation_engine.py`, `core/reporter.py`, `core/pdf_reporter.py`, `core/config.py`, `scanners/base.py` + 19 scanners, `main.py`, `gui/services/scan_worker.py`, `gui/controllers/scan_controller.py`, `templates/report.html.j2`, `test_validation.py`.
- **Unchanged:** `core/{evidence,response_analyzer,payload_mutator,utils,http_client,crawler,js_crawler,js_analyzer,browser,ssrf_guard,oast_manager,auth_manager,secrets_redactor}.py`, GUI widgets/pages.

---

## 12. Validation Strategy

### 12.1 Offline unit tests (no network)
- `test_validation.py` extended with:
  - Each new engine imports and returns typed outputs for fixture findings.
  - Confidence/verification/severity/risk reproduce the exact v2.x numbers on a fixed corpus
    (golden regression corpus serialised under `tests/fixtures/`).
  - Coverage reconciles: `executed + skipped + not_applicable == total` and
    `skipped == len(get_skipped_findings())` (fixes the strict-validation quirk).
  - Assessment `to_dict()` emits every v2 `statistics` key (shape test).
  - Scanner evidence-only rule test: a mocked scanner result is rejected if it sets
    `severity`/`confidence`/`verification_status` directly (guards Phase A8).

### 12.2 Regression gate
- `python test_validation.py` must exit with **0 errors / 0 warnings** after every phase.
- `python -m compileall -q core scanners gui main.py` clean.
- GUI smoke test (`%TEMP%\opencode\gui_smoke_test_v2.py`) passes offscreen after Phase A9.

### 12.3 Live comparison (Phase B2)
- Scan a stable target (e.g. `https://example.com`) before and after each phase.
- Compare `risk_score`, `overall_*`, per-module `severity/confidence/verification`.
- Old-vs-new diffs must be nil for Phases A1–A7 (engine parity) and reviewed for A8+.
- Reports (HTML/JSON/Markdown/PDF) generate successfully with `strict_validation=True`.

### 12.4 Rollback rule
Any phase that breaks the regression gate is reverted or fixed **before** the next phase begins;
the codebase remains shippable at every commit.

---

## 13. Optional Authentication (SOP v4.0 Phase 1)

Authentication is an **opt-in transport feature** that wraps the anonymous pipeline; it never
changes the anonymous default and never touches the assessment engines.

- **`core/auth/`** — standalone provider package (`AuthSpec` + `BaseProvider`; `cookie_provider`,
  `bearer_provider`, `jwt_provider`, `header_provider`). Builds an in-memory `AuthSession`
  (`core/auth_manager.py`) from the `AuthSpec`; secrets stay in memory and are always redacted.
- **`AuthenticationManager`** — facade: `build(spec)` returns `None` for anonymous (no-op),
  raises `ValueError` on unsupported/empty credentials; `apply_to`/`activate` attaches the session
  to the transport; `validate` runs only when enabled; `mark_invalid` flags token methods
  `token_invalid` / cookies `session_expired` so a failed session is never reported as authenticated.
- **`SessionValidator`** — probes the target with a **fresh** `requests.Session()` (the tracked
  crawl session is never mutated) and rejects on 401/403, redirect-to-login, or a login-page body.
  On failure the caller prints a clear warning and continues anonymously.
- **Login detection** (existing `AuthDetector`) is informational only: a non-blocking hint that
  authentication is available; it never forces or blocks.
- **Scanners / crawler contain no auth logic.** The pipeline (`§1.2`) is unchanged; auth only
  configures the `TrackedSession` that scanners already receive.
- **Reporting**: `stats['auth']` carries `mode`/`authenticated`/`session_valid`/`session_checked`;
  the HTML Authentication section renders Mode, Authenticated, Session Valid and Protected Pages
  Scanned. Anonymous scans render no auth section.

---

*End of specification. Review, amend, and approve before implementation begins.*
