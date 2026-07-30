# Standard Operating Procedure — SEA Corporate Security Scanner (scanner_v4)

## 1. Quick Architecture Overview

```
scanner_v4/
├── main.py                  # SeaScanner orchestrator — full scan lifecycle
├── core/                    # Shared engine (11 files)
│   ├── finding.py           # Finding / Severity / Status / ScanResult
│   ├── evidence.py          # Evidence + EvidenceBuilder
│   ├── decision_engine.py   # STANDARDS map (CWE/OWASP/CAPEC/MITRE/ASVS) + CVSS + RiskCalculator
│   ├── verification_engine.py # 4 passes: initial/confirmation/cross-validation/behavioral
│   ├── response_analyzer.py # Response analysis, security headers, tech detection, similarity
│   ├── correlation_engine.py# 10 cross-finding correlation rules
│   ├── reporter.py          # 1,812 lines — every report format (HTML/JSON/MD/CSV/TXT)
│   ├── crawler.py / js_crawler.py / browser.py
│   ├── http_client.py       # TrackedSession + ResponseCache
│   └── config.py            # ScanConfig (branding, workers, timeouts...)
├── scanners/                # 18 scanners + base.py (BaseScanner + SmartPayloadSystem) + registry.py
├── test_validation.py       # 200+ checks — mandatory quality gate
├── backend/app/             # FastAPI (models, schemas, scan_runner, main) + SQLite
├── frontend/src/            # React + Vite — Dashboard/Scans/Reports/Users...
└── project_docs/            # Documentation (SSOT)
```

**Key distinction**: editing `core/` or `scanners/` affects detection results/accuracy; editing `backend/` or `frontend/` affects experience only.

## 2. General Principles

- **Work in phases**, never a full rewrite.
- **PROJECT_STATE.md is the SSOT**. Read it + `development_progress.txt` + `CHANGELOG.md` before writing code.
- **Backward compatibility** — never remove/rename a public method/class without an alias.
- **`test_validation.py` must pass** with 0 errors / 0 warnings after every change.
- **No feature bloat** — every new feature must answer: "Does this increase detection accuracy, user trust, or commercial quality?"

## 3. SOP #1 — Daily Development Workflow

### Step 1: Read context
```bash
cat PROJECT_STATE.md
cat project_docs/development_progress.txt
tail -50 project_docs/CHANGELOG.md
```

### Step 2: Define scope
Pick exactly one unit: a specific scanner, shared engine (`core/*.py`), report (`core/reporter.py`), backend, or frontend. Never touch more than one layer in the same commit.

### Step 3: Implement the change
- Follow existing patterns (BaseScanner, SmartPayloadSystem, EvidenceBuilder, verify_multi_pass)
- New/modified scanners: use `create_safe_finding()` / `create_vulnerable_finding()`, `verify_multi_pass()` (≥2/3 passes), `add_verification_evidence()` + `capture_response_analysis()`

### Step 4: Run quality gate
```bash
python test_validation.py
```
Must show 0 errors, 0 warnings.

### Step 5: Live test
```bash
python main.py
```
Test against a live target (e.g. testphp.vulnweb.com or local environment).

### Step 6: Update documentation
- New line in `project_docs/CHANGELOG.md`
- Update `PROJECT_STATE.md` (Recent Changes, Completed Features)
- Bug fix: add to `BUGS.md` under "Fixed" with new ID (B14, B15...)
- Architectural decision: add to `DECISIONS.md` (D22...)

### Step 7: Git commit
```bash
git add <only relevant files>
git commit -m "type(scope): short description

- detail 1
- detail 2
Refs: BUGS.md#B14"
```
Convention: `fix(sqli):`, `feat(reporter):`, `docs:`, `refactor(core):`

## 4. SOP #2 — Adding a New Scanner

1. Create `scanners/new_scanner.py`, inheriting from `BaseScanner`.
2. Decide: Host-level (once per domain) or Page-level (every crawled page).
3. Build payloads via `SmartPayloadSystem.select_payloads()` or scanner-specific payloads.
4. Implement `scan()` returning a Finding via `create_safe_finding()` or `create_vulnerable_finding()`.
5. Wire in multi-pass verification via `verify_multi_pass()`.
6. Add evidence via `add_evidence_with_snippet()` or `capture_http_evidence()`.
7. Register in `scanners/registry.py`: import → add to `PAGE_LEVEL_SCANNERS` or `HOST_LEVEL_SCANNERS` → add to `_SCANNER_NAME_MAP`.
8. Add mapping in `core/decision_engine.py` inside `STANDARDS` dict.
9. Add test in `test_validation.py` (import, registry, instantiation checks).
10. Update `README.md` (scanner count), `ARCHITECTURE.md`, `PROJECT_STATE.md`.
11. Run `test_validation.py` + live test.

## 5. SOP #3 — Bug Fixing Protocol

### a) Classify the bug
- Detection bug (FP/FN) → high priority
- Report/display bug → medium priority
- Performance/concurrency bug → depends on load
- Dependency bug → low priority

### b) Diagnosis
- Reproduce with concrete example.
- Identify responsible file.
- Determine: logic bug or data/mapping bug?
- Capture faulty behavior.

### c) The fix
- Local and focused — don't rewrite the whole file.
- If touching multiple scanners, call out in commit.
- Add regression test in `test_validation.py`.

### d) Verification
```bash
python test_validation.py     # must be 0/0
python main.py                # live test on 2-3 targets
```

### e) Documentation
- Log in `BUGS.md` under "Fixed" (new ID), add to `CHANGELOG.md`, update `PROJECT_STATE.md` if accuracy affected.

### Currently open bugs
| ID | Issue | Priority |
|----|-------|----------|
| B9 | `ScanResult.add_finding()` not thread-safe | Medium |
| B12 | Missing optional libraries silently degrade functionality | Low |
| B13 | Shared mutable attributes across threads in scanners | Medium |

**Fix for B9/B13**: add `threading.Lock()` around `add_finding()` and make `run_page_scan()` instantiate a fresh scanner per thread.

## 6. SOP #4 — Improving the Report Format

### a) Before any visual change
Save baseline: `python main.py` (choose HTML), `cp reports/report_XXXX.html /tmp/baseline_report.html`.

### b) Where to edit
| Change | Function |
|--------|----------|
| CSS/style | `<style>` block (~line 310+) |
| Severity section | `build_finding_section()` |
| Warnings section | `build_warning_section()` |
| "No issues" | `build_safe_section()` |
| Informational | `build_info_section()` |
| Colors by severity | `get_color()` |
| Full HTML structure | `build_html()` |
| Other formats | `generate_json/markdown/csv/txt()` |

### c) Mandatory rules
- Escape all external text via `_escape_html()`.
- Add new fields to all formats (HTML/JSON/CSV/MD/TXT).
- Respect `max_items=20` in `_render_list()`.
- Check dark mode + print CSS for every new visual element.

### d) After change
- Compare new report against baseline.
- Confirm copy-to-clipboard (curl replay) still works.
- Run `test_validation.py`.

### e) Suggested improvements
- Split `<style>` into external CSS or Jinja2 template.
- Use Jinja2 templates (empty `templates/` folder exists).
- Add SVG chart for risk breakdown.

## 7. SOP #5 — Working with Backend (FastAPI) and Frontend (React)

- **Backend**: model changes need migration (consider Alembic). Mirror SeaScanner/ScanConfig signature changes in `scan_runner.py`. Test endpoints with curl/Postman.
- **Frontend**: confirm pages wire to real endpoints (`api.ts`), not mock data. Distinguish full HTML report vs. React dashboard view.

## 8. SOP #6 — Release Checklist

- [ ] `python test_validation.py` → 0 errors, 0 warnings
- [ ] Live test on 3 different targets
- [ ] Report generates in all formats (HTML/JSON/MD/CSV/TXT)
- [ ] Dark mode + print CSS confirmed
- [ ] `CHANGELOG.md` updated
- [ ] `PROJECT_STATE.md` updated
- [ ] `BUGS.md` updated if fixes applied
- [ ] `README.md` reflects actual count
- [ ] `requirements.txt` updated if libraries added
- [ ] Git tag with version (e.g. v2.1.0)

## 9. Suggested Priorities

1. Fix B9/B13 (thread safety) — prerequisite for concurrent scans
2. Extract HTML template from `reporter.py` into Jinja2 — maintainability
3. Advanced Parameter Discovery + DOM-based XSS — after stability proven
4. Docker + CI/CD — for commercial packaging/deployment
