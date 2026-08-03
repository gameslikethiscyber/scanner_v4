# Phase 4.1 — Confidence Calibration Audit

Analysis-only deliverable. No engine logic was changed; the entire assessment
pipeline was read and documented to plan Phase 4.2+ (normalization) with a
zero-regression strategy. Reference baseline: tag `v4.9.0` (Phase 3).

---

## 1. Executive summary

The pipeline is already correctly layered and every finding flows through a
single chain, but confidence is produced by **two independent, never-reconciled
systems**:

1. **Engine confidence** (`finding.confidence`, 0-100) — computed by the
   Evidence Engine → Confidence Engine from evidence levels/weights/caps. This is
   the number that actually drives risk, CVSS and reports.
2. **Scanner/domain confidence** (`fingerprint['*_confidence']`, 0-100) — ad-hoc
   per-scanner heuristics (cookie, header, http-methods, sensitive-files, cors,
   sqli database). Stored in fingerprints and **never consumed** by the engines.

That split, plus several duplicated constants/calculators and a coarse bonus
scheme, is the root cause of cross-scanner inconsistency. The audit documents
all of it with file/line evidence and a phased, regression-locked remediation.

---

## 2. Current confidence architecture

### 2.1 The one true chain (per finding)

```
Scanner scan()  ──►  Finding.evidence[]        (raw, scanner-owned only)
        │
        ▼
EvidenceEngine.score(evidence)  ──► EvidenceScore   core/evidence_engine.py:58
        │   weighted_bonus / total_weight / evidence_quality / strongest_level
        ▼
ConfidenceEngine.compute()      ──► ConfidenceResult  core/confidence_engine.py:46
        │   finding.confidence, confidence_factors, confidence_explanation
        ▼
VerificationEngine.classify()   ──► VerificationClassification  core/verification_engine.py:222
        │   finding.verification_status / verification_class / passes
        ▼
SeverityEngine.assess()         ──► SeverityResult  core/severity_engine.py:61
        │   severity / exploitability / impact / CVSS
        ▼
   (per finding)  run_engine_pipeline()  core/pipeline.py:35
        │
        ▼
CorrelationEngine.correlation_payloads()  ▶ boosts / escalations / risk multipliers
        │
        ▼
RiskEngine.calculate()          ──► RiskResult  core/risk_engine.py:50   (scan-wide risk score)
CoverageEngine.report()         ──► CoverageReport  core/coverage_engine.py:59
AssessmentEngine.build()        ──► Assessment  core/assessment_engine.py:66
   overall_verdict + assessment_confidence + statistics
```

All production scanners run through `BaseScanner.run()` →
`core.pipeline.run_engine_pipeline()` (`scanners/base.py:84`), so the chain is
**uniform — no legacy/migrated divergence** in the live path.

### 2.2 Evidence → Confidence

`EvidenceEngine.score()` produces two distinct numbers that are NOT the same:

- `weighted_bonus / total_weight` — a *weighted average of each evidence's
static `confidence_bonus`* (only positive bonuses count; weights 1–5),
  encoded in `evidence.py:47-125`: verified/exploited/request_response
  bonus 25/35, confirmed 20, likely 10, possible 5.
- `evidence_quality` (0–100) — `LEVEL_QUALITY` base (exploited 100 → not_tested
  10) + payload/parameter/raw/verification bonuses − error penalty
  (`evidence_engine.py:124-153`). **This value is attached but never feeds
  `finding.confidence`.**

`ConfidenceEngine.compute()` (`confidence_engine.py:46`):
- base = `weighted_bonus / total_weight + BASE_ANCHOR(50)` (parity formula).
- +5 multiple-evidence; +5/+10 single/multi verification pass; +10
  cross-validation.
- max-confidence cap chain from strongest level sequence
  (95 start; exploited 100, verified 90, confirmed 85, likely 75, possible 60,
  error 40) at lines 94–127.
- output = `clamp(0, min(base, cap))`, with optional correlation/cross-validated
  boosts.

### 2.3 Confidence → Verification vocabulary (note the two cut-sets)

`VerificationEngine.classify()` uses **its own, independent bands**
(`verified.py:208-211`): confirmed ≥95, likely 80–94, possible 55–79,
manual 35–54, else unverified; hard overrides: no/error evidence → unverified;
exploited OR verified evidence → confirmed. Report map replaces internal
`confirmed` → `verified` (`pipeline.py:182`).

These bands (95/80/55/35) are **different numbers** from the Confidence Engine's
caps (100/90/85/75/60/40). They are not coordinated: a finding whose evidence is
`confirmed`-level but scores, e.g., 75 lands in `possible`, contradicting the
evidence label.

### 2.4 Scanner fingerprint confidence (the second, independent system)

Each scanning family computes its own confidence heuristic and stores it in the
finding fingerprint. Verified via grep across `scanners/*.py`:
- Cookie: `cookie_confidence` (`scanners/cookies.py:204,263`)
- Headers: `header_confidence` (`scanners/headers.py:106`)
- HTTP Methods: `http_methods_confidence` (`scanners/http_methods.py:68`)
- Sensitive Files: `sensitive_confidence` (`scanners/sensitive_files.py:99,118`)
- CORS: `cors_confidence` (`scanners/cors.py:250`)
- SQLi: per-DB `database_confidence` (`scanners/sqli.py:345,765`)

None of these is read back by the Evidence/Confidence/Risk/Severity engines.
They are descriptive labels in the report, not scoring inputs.

---

## 3. Current risk architecture

- **Formula** (`risk_engine.py:44-48`):
  `risk_score = Σ(severity_weight × (confidence/100) × verification_multiplier × (0.8+0.2×occurrences_factor)) / Σ(severity_weight) × 100`
- `SEVERITY_WEIGHTS`: crit 10 / high 7 / med 5 / low 3 / info 1 / none 0
  (`risk_engine.py:23`; duplicated at `decision_engine.py:254`).
- `VERIFICATION_MULTIPLIERS` for vulnerable findings: confirmed 1.0, verified
  1.0, likely 0.85, possible 0.6, manual_review 0.4, unverified 0.3
(`risk_engine.py:28-31`). **`RiskCalculator`'s copy is missing `confirmed`**
   (`decision_engine.py:259-262`).
- Warnings contribute at half severity weight and are divided under twice the
  possible weight (`risk_engine.py:101-118`).
- Correlation risk multipliers multiply a module's contribution
  (`risk_engine.py:76`, `correlation_engine.py:29-106`), clamped to not exceed
  the cap.

### Risk duplication
Two near-identical implementations exist:
- `RiskEngine` (canonical; used by the pipeline).
- `RiskCalculator` (legacy; used only when `ScanResult.assessment` is absent —
  fallback path in `finding.py:856-867`).
Same formula, but they can drift independently (already one:
`VERIFICATION_MULTIPLIERS` missing `confirmed` in `RiskCalculator`).

---

## 4. Severity mapping review

- Single source of truth: `DecisionEngine.STANDARDS` → `SEVERITY_BY_MODULE`
  (`decision_engine.py:250`); scanner-preset severity is ignored (A8.9 freeze).
- `SeverityEngine` (`severity_engine.py:61-107`): PASS/SAFE → NONE;
  FAIL/VULNERABLE/WARNING → module base; else INFO.
- Optional correlation upward escalation only.
- "Unverified critical → high" is only applied via an opt-in parameter that the
  pipeline passes as `None` (`pipeline.py:72-76`), so **per-finding critical
  findings are never downgraded** — the policy lives only in the overall verdict
  text (`assessment_engine.py:164-166`).
- Impact multipliers, exploitability-from-severity, CVSS base per severity
  (`severity_engine.py:37-53`).
- CVSS score = module severity base + `(confidence/100)*0.5` additively re-scaled
  (`severity_engine.py:122`) — so **CVSS is confidence-dependent**, which can
  produce different CVSS for two findings of identical impact because their
  confidence differs.

## 5. Risk calculation review

- Lengthy transparent breakdown + formula string (good for reporting).
- Sensitivities:
  - Linear in confidence (a 1-point confidence change moves the score linearly).
  - Severity weight is module-derived, independent of confidence → a
    low-confidence critical (say 35%) contributes only
    `10 × 0.35 × mult` — under-weighted relative to a medium-confidence medium.
  - Occurrence cap is **1–5** with a floor 0.8; aggregation via `merge()` can
    inflate occurrences across page findings.
- Overall verdict multi-factor logic (`assessment_engine.py:139-225`) re-derives
  severity from counts/risk and can refuse a CRITICAL label (reports HIGH) when
  criticals are unverified — again coupling verdict to verification, not to
  raw impact.

---

## 6. Identified inconsistencies (the audit's core findings)

| ID | Category | Finding | Ref |
|----|----------|---------|-----|
| C1 | Two-systems | Scanner fingerprint `*_confidence` (0-100, per-family) coexists with engine `finding.confidence` (0-100, evidence-derived) with **no reconciliation** — a source of hard-to-debug cross-scanner skew. | `scanners/*`, `pipeline.py:44-58` |
| C2 | Dead signal | `EvidenceEngine.evidence_quality` is computed but **not used** for confidence (confidence uses only bonus-weighted average). | `evidence_engine.py:124-153` vs `confidence_engine.py:68-92` |
| C3 | Band/cap drift | Verification bands (95/80/55/35) vs confidence caps (100/90/85/75/60/40) are two uncoordinated cut-sets; a single `confirmed` evidence at conf 75 reports `possible`. | `verification_engine.py:208-244`, `confidence_engine.py:35-41` |
| C4 | Duplicate risk | `RiskEngine` and `RiskCalculator` duplicate the formula; `RiskCalculator` lacks `confirmed` in its verification map. | `risk_engine.py:28-31`, `decision_engine.py:259-262` |
| C5 | CVSS duplicate/shift | CVSS is a function of confidence (`severity_engine.py:122`), which already contains confidence from evidence; two equal-impact findings with different confidence → different CVSS. | `severity_engine.py:119-165` |
| C6 | Assessment-scale mix | `assessment_confidence` (start at 100 − skipped/failed/coverage + verified − unverified; `assessment_engine.py:229-274`) is a **different scale** from risk_score and per-finding confidence → report users can't compare. | `assessment_engine.py:267-274` |
| C7 | Uncapped policy | "unverified critical → high" is only text (`verdict` path), never applied per-finding (pipeline passes `verification_status=None`). | `pipeline.py:72-76`, `severity_engine.py:86-88` |
| C8 | Constant sprawl | the same constants (caps, multipliers, weights, bands) live in multiple files with some drift already observed. | see refs above |

### Missing normalization points
- Main missing point: a **single confidence scale** (evidence-derived) is not
  propagated to scanner fingerprint values, and vice-versa.
- No cross-scanner equivalence guarantees (two modules that produce the same
  evidence pedigree yield different confidence because they use different
  heuristics to *name* evidence).
- No monotonicity/ties test in the suites that would catch this drift.

---

## 7. Proposed normalization strategy

Goal: **one confidence vocabulary, one risk formula, one set of constants**,
with scanners contributing calibrated *signals* (not competing numbers).

1. **Confirm `finding.confidence` as the single scoring = confidence.**
   Keep the chain `Evidence → Confidence → Verification → Severity` as the only
   scorer. Treat scanner fingerprint `*_confidence` as **reported signals** that
   the ConfidenceEngine *may* blend in, with a documented, capped contribution
   (Scheme B, below) — never as an alternative score that survives in reports as
   if it were a competitor.

2. **Close C2:** feed `evidence_quality` into the confidence base (replacing or
   refining the `BASE_ANCHOR` + static-bonus average) through a documented
   formula, preserving parity behind a flag.

3. **Align the two cut-sets (C3):** make verification bands derived from the
   Confidence Engine's caps, and let `confirmed`-level evidence place at least in
   the `likely`/`confirmed` band, and add an exact-once rule for evidence levels.

4. **Single constants source (C8):** one `CONFIDENCE_CONFIG`
   (`core/config.py` + `core/assessment.config`) referenced by Evidence,
   Confidence, Verification, Coverage engines; delete file-local duplicates.

5. **Collapse duplicate risk (C4):** keep `RiskEngine` as the only owner; a thin
   alias for `RiskCalculator` for phase-B parity asserts; extend the shared
   verification map to include `confirmed` in one place.

6. **Normalize CVSS independence (C5):** derive CVSS from severity + impact only,
   OR keep the confidence term but document it once and derive it from a
   normalized tag — decide in P4.4 with parity snapshot.

7. **Unify project-level score (C6):** express `assessment_confidence` as a
   documented simple composition (e.g., risk_score ↔ confidence) with a single
   explanation; add a validation rule that overall verdict never contradicts the
   highest-confidence-critical/high evidence (already partially present in
   `ScanResult.validate`).

---

## 8. Expected benefits (P4.2+)

- Cross-scanner comparability: identical evidence pedigree → identical
  confidence regardless of module.
- Single, auditable score: no competing "cookie_confidence vs
  engine.confidence" — one number drives risk/CVSS/severity/verdict.
- Reduction of false splits from drifted caps/multipliers.
- Consistent risk: severity weighting + confidence + verification all share one
  composed vocabulary.
- Maintainable because constants centralized and parity is CI-checked.

---

## 9. Migration plan (analysis → zero-risk rollout)

| Step | Scope | Behavior change | Gate |
|------|-------|------|------------|
| P4.2 | Instrumentation: add audit/diagnostics (per-finding `evidence_quality`, actual `*-_confidence`) — `CALIBRATION_REPORT` mode | none | report parity |
| P4.3 | Centralize constants in `CONFIDENCE_CONFIG`; snap v2 reference outputs from `tests/v2_reference.py` | none (pure refactor) | engine regression 0/0, REGRESSION=0 |
| P4.4 | Introduce the judgment algorithm behind `SEA_CALIBRATE` env flag off by default; A/B demonstrate parity | exceeds registry | no default output change |
| P4.5 | Wire scanner fingerprint `*_confidence` as **optional capped signals** into Confidence Engine | only AFTER P4.4 flag | compare A/B |
| P4.6 | Collapse `RiskCalculator` → `RiskEngine`; centralize verification vocabulary & constant-dedup | default-off parity, then on | full suite + snapshot-to-`v2_reference` diff = 0 |
| P4.7 | Add cross-scanner calibration + monotonicity + dead-code tests; finalize docs; release | flip default on | REGRESSION=0 |

The rollout is incremental; nothing changes for consumers until a calibration
branch is flipped, and each stage re-runs the three gates.

---

## 10. Zero-regression strategy (must hold)

- **Gates (all green today, must stay green):**
  `test_validation`: 0 errors/0 real failures; `tests/engine_tests.py`: 0/0;
  `tests/regression_runner.py`: `REGRESSION=0` (PASS=10, WARNING=6).
- **Parity oracle:** `tests/v2_reference.py` golden outputs for canonical
  scenarios (`tests/fixtures/golden/*.json`). Any refactor that would change a
  score must first prove exact-match against goldens; new messages re-recorded
  by an explicit, reviewed snapshot diff.
- **Feature flag:** actual scoring only changes inside `SEA_CALIBRATION`.
  Default behavior after each step stays byte-identical to v4.9.0; the flag can
  be rolled back without code revert.
- **No new scanners** (per Phase 4 scope). All work is in `core/` + tests.
- Each P4.x ends with: engine 0/0, REGRESSION=0, and (if a number changed)
  an explicit v2-reference diff = 0 or a reviewed snapshot.

---

## 11. Next step (awaiting approval)

P4.1 deliverable is complete (this report). Approval to proceed with **P4.2:
constant centralization + parity snapshot + instrument `evidence_quality` /
fingerprint-confidence capture**. Once approved, work begins strictly
under the zero-regression gates above and **no output-visible change** until
the calibration flag is switched.