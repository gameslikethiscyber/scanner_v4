# Phase 4.2 — Engine Calibration Foundation

Behavioral parity milestone. This phase built the *foundation* for confidence
normalization without changing any visible number. **No consumer-visible change:
confidence, risk, severity, report, and assessment output are byte-identical to
the v4.9.0 (Phase 3) baseline.**

Gates after this phase: `validation 0 errors / 0 real failures`, engine tests
`0/0`, regression `REGRESSION=0` (PASS=10, WARNING=6).

---

## 0. Updated architecture diagram (P4.2 viewpoint)

```
 scanners/*.scan()  ──►  Finding.evidence[]            (scanner-owned only)
        │
        ▼
  core/assessment_config.py   ◄══ SINGLE SOURCE OF TRUTH (constants)
        │        (EVIDENCE|CONFIDENCE|VERIFICATION|SEVERITY|RISK|COVERAGE|ASSESSMENT)
        ▼
 EvidenceEngine.score() ──► EvidenceScore
        ▼            (bonus average  +  evidence_quality [observed, not used])
 ConfidenceEngine.compute() ──► ConfidenceResult  (base + bonuses + caps)
        ▼
 VerificationEngine.classify() ──► bands (95/80/55/35)
        ▼
 SeverityEngine.assess() ──► SeverityResult (module base + CVSS)
        ▼
 run_engine_pipeline()  FEATURE FLAGS: core/feature_flags.py (SEA_CALIBRATION=off)
        │                  └─ INSTRUMENT: CalibrationCollector.record_finding()
        ▼
 RiskEngine.calculate()  ──► RiskResult   |  (RiskCalculator legacy→config too)
 CoverageEngine.report() ──► CoverageReport
 AssessmentEngine.build() ──► Assessment (statistics, assessment_confidence)
        │                   └─► record_scan() + save()  (gated diagnostics)
        ▼
 consumer outputs (reporters / GUI / CLI / backend)
```

New (P4.2) building blocks shown dashed: the **single constants source** and the
**gated instrumentation hook**. Both are inert by default.

---

## 1. Centralized constants (`core/assessment_config.py`)

The P4.1 audit (C8) flagged duplicated constants/drift across files. New module
is the only owner; every engine now imports from it:

| Section | What it unifies | Previously defined where |
|---------|-----------------|--------------------------|
| `EVIDENCE`   | Level quality, bonuses, raw-key bonuses | `evidence_engine.py` |
| `CONFIDENCE` | anchor, bonus ajustes, caps, level order | `confidence_engine.py` |
| `VERIFICATION` | bands 95/80/55/35, labels, report map | `verification_engine.py` + `pipeline.py` |
| `SEVERITY`   | CVSS base, impact multiplier, verified statuses, order | `severity_engine.py` |
| `RISK`       | severity weights, verification multipliers, occurrence/grade | `risk_engine.py` + `decision_engine.RiskCalculator` |
| `COVERAGE`   | penalties, confidence-impact scale | `coverage_engine.py` |
| `ASSESSMENT` | penalties, verified/unverified statuses | `assessment_engine.py` |

Every value is **byte-identical** to the frozen defaults; unified namespace makes
the future calibration edit a single change.

**Engine references updated (no logic change):**
`confidence_engine`, `evidence_engine`, `verification_engine`, `severity_engine`,
`risk_engine`, `coverage_engine`, `assessment_engine`, `decision_engine.RiskCalculator`,
`pipeline` (report map).

---

## 3. Feature flag + instrumentation (`core/feature_flags.py`)

- Env flag `SEA_CALIBRATION` (default `off` / stable mode).
  - `off` → whole module inert.
  - `report` → `CalibrationCollector` records per-finding and scan-level observations
    (module, status, engine confidence, evidence_quality, verification, severity,
    evidence_count, fingerprint `*_confidence`) to `SEA_CALIBRATION_DIR` (default
    `reports/calibration`, git-ignored).
- Wired into `core/pipeline.py` at both endpoints; **no effect on any scoring
  code path** and proven inert: running the whole regression under
  `SEA_CALIBRATION=report` still yields `REGRESSION=0`.

### Instrumentation report
- Confirmed the collector captures and emits diagnostics (`calibration_diagnostics_*.json`).
- The collector exposes, per finding: raw vs domain confidence (engine
  confidence vs fingerprint), evidence_quality (currently unused — C2), status/severity.

---

## 4. Parity snapshot & guard

- `tests/calibration_capture.py` — deterministic canonical scenarios
  (verified/confirmed single/multi/likely/possible/error/host-reflected/verified)
  through the real pipeline → `tests/fixtures/calibration/parity_baseline.json`.
- `tests/calibration_parity_test.py` — recomputes and asserts exact equality to the
  baseline. Any class file that changes a visible number must fail here until a
  reviewed snapshot is applied.
- Status: `PARITY=0  calibration output matches frozen baseline.`

Notable frozen observations (recorded, NOT changed — P4.2 is behavior-free; these
are inputs to P4.3): `confirmed` evidence reports `possible`; a `verified`-only
finding maps status `pass`; `evidence_quality` is not reflected in confidence. These
prove the C1/C2/C3 audit findings and are explicit calibration targets.

---

## 5. Regression report (all green, parity held)

| Gate | Result |
|------|--------|
| `python -m test_validation` | Errors: 0 · real fails: 0 |
| `python -m tests.engine_tests` | Errors 0 / Warnings 0 |
| `python -m tests.regression_runner` | **REGRESSION=0** (PASS=10, WARNING=6) |
| `python -m tests.regression_runner` (flag ON) | **REGRESSION=0** (flag inert) |
| `python -m tests.calibration_parity_test` | **PARITY=0** (matches frozen baseline) |

---

## 6. What comes next (P4.3, not started)
Normalize per-finding confidence (use `evidence_quality`, reconcile bands+caps,
optionally feed scanner fingerprint confidence as calibrated signal) — **only under
the `SEA_CALIBRATION` gate**, continuing to hold `PARITY` and `REGRESSION` via the
new baseline guard.

Stop: Phase 4.2 is complete. Confidence normalization is NOT enabled.