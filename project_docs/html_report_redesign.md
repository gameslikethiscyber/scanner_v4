# Professional HTML Report Redesign (v4.12.0 → presentation)

A presentation-only overhaul of the SEA Corporate HTML report to
commercial-grade / enterprise quality. The scanner and assessment engines are
**frozen** at v4.12.0 — no engine, assessment, or data code changed.

## Objectives
- Executive-dashboard landing (verdict hero, KPI cards, donut, risk gauge).
- Severity cards with boxed reason + recommendation + collapsible evidence.
- Light / dark / system themes, sticky TOC, print-to-PDF support.
- Responsive (desktop / tablet / 390px mobile) and offline-safe (no CDNs/fonts).
- **Presentation only** — all existing report data is preserved.

## Files changed
- `templates/report.html.j2` — full rewrite (design tokens, themes, layout,
  charts, print CSS).
- `core/reporter.py` — markup/CSS-class-only edits:
  - findings: `finding-card.finding-{sev}`, `reason-box`, `recommend-box`,
    `details.http-block` evidence (native, no JS), `section-title`/`st-count`.
  - executive summary: `.es-head/.es-badge/.es-body/.exec-meta`.
  - risk breakdown: `.rb-formula/.rb-total/.rb-risk/.rb-summary` +
    `.table-wrap` (scrollable 5-col table).
  - coverage skip reasons: `.coverage-skip-note/.cs-item`; scan summary:
    `.scan-summary`.
  - attack surface: inline stroke-SVG icons via `_icon()` (emojis removed).
- `tools/report_sample.py` (new) — builds deterministic scenario reports through
  the **production** `Reporter.generate_html` path (same filtering + validation
  as the CLI) so samples match deployed output exactly.
- `tools/report_visuals.py` (new) — Playwright screenshots (light/dark,
  1440px/390px) + A4 print PDF.

## Design system
- Tokens in `:root` / `[data-theme="dark"]` (`--bg/surface/border/text/accent`,
  severity palette, chart track, radii, shadows). `color-scheme` per theme.
- Charts are pure CSS: conic-gradient donut (severity distribution) and risk
  ring gauge (`g-band-ok/warn/err` by risk tier) — no charting library, so
  generation stays fast and offline.
- Native `<details>/<summary>` for all collapsible evidence (accessible, no JS
  required). `@media print` forces every collapsible block open and hides TOC/
  buttons so print/PDF output contains full detail.
- Theme toggle persists via `localStorage`; follows system on first visit.
- No literal `&` anywhere in output (inline JS uses nested `if`, separators are
  literal UTF-8) — satisfies the `test_validation.py` escaping contract.

## Before / after
Artifacts under `reports/screenshots/` (gitignored, local only):
- `mixed_corpus_before_*.png` / `mixed_corpus_before_print.pdf` — original template.
- `mixed_corpus_after_{light,dark}_{1440,390}px.png`, `mixed_corpus_after_print.pdf`.
- `clean_site_{light,dark}_{1440,390}px.png`, `clean_site_print.pdf`.

Sample HTML reports: `reports/samples/{mixed_corpus,clean_site}.html`.

Regenerate with:
```
python tools/report_sample.py --out reports/samples
python tools/report_visuals.py reports/samples/mixed_corpus.html --out reports/screenshots
python tools/report_visuals.py reports/samples/clean_site.html --out reports/screenshots
```

## Performance validation
- `Reporter.generate_html` (full report, assessed mixed_corpus scenario):
  **~43.7 ms/report**, ~85 KB HTML — inline CSS/JS only, no network requests.

## Quality gates (all green after redesign)
- Validation: `0/0` (`test_validation.py`).
- Engine: `0/0` (`python -m tests.engine_tests`).
- Regression: `PASS=10  WARNING=6  REGRESSION=0`.
- Calibration parity: `PARITY=0`.

## Verified rendering (Playwright audit)
- No horizontal overflow at 1440 / 1024 / 390 px.
- Donut + gauge + legend + finding cards internally consistent (chart counts
  equal FAIL/VULNERABLE finding counts; clean site → 0-finding donut, ok band).
- Theme toggle persists across reload; no console errors; no unrendered Jinja
  (`{{ }}`) leaks; TOC anchors all resolve; print mode opens all details.
