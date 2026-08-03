# SEA Scanner Pro — Final UI Polish & UX Review Report

**Version**: GUI v2.0.0 (Engine frozen v4.12.0) · **Date**: 2026-08-03
**Scope**: Holy-water quality pass across the entire desktop application,
reviewed as a first-time customer. **No new features** — only UX improvements.
Gates held: `REGRESSION=0`, `PARITY=0`, validation `0/0`, engine `0/0`.

---

## 1. User Journey Walkthrough

The full journey was exercised (programmatically through the headless harness +
direct controller wiring, and reviewed in code):

| # | Step | Pathway | Status |
|---|------|---------|--------|
| 1 | Launch application | `app.py` → theme → MainWindow → Overview | OK |
| 2 | Configure a scan | Scanner Setup: target, mode, threads, timeout, auth, crawl | OK |
| 3 | Run a scan | Start Scan → Setup → Running | OK |
| 4 | Monitor progress | Stage label, progress bar, elapsed, ETA, live logs | OK |
| 5 | Review results | Completed state → SummaryView (risk, KPIs, findings table) | OK |
| 6 | Open HTML report | `open_report_btn` → QDesktopServices → report path | OK |
| 7 | Open PDF report | Via HTML widgets, entries carry `report_paths` | OK |
| 8 | Export reports | Save Logs; engine writes HTML/JSON/MD/CSV/TXT in Settings | OK |
| 9 | Review history | History master–detail → SummaryView | OK |
| 10 | Change settings | Settings page → persisted JSON → immediate apply | OK |

Each state (empty / loading / error / success) was inspected and hardened (see
§3).

---

## 2. Visual QA Checklist

Reviewed across **dark and light** themes for every page. ✓ = compliant.

- [x] **Visual consistency**: single design system (indigo accent `#4F46E5`,
      report-aligned severity scale) applied to every page; KPI icons now use a
      consistent accent-soft chip.
- [x] **Spacing & alignment**: uniform 32/24px page margins, 16px card gap,
      8–12px intra-card spacing; stretch factors balanced (risk meter 3 : KPI
      column 2).
- [x] **Typography hierarchy**: kicker (10.5px) → title (22px) → subtitle (13px);
      KPI values 30px, section headers 18px, body 13px. Consistent weights.
- [x] **Icon consistency**: stroke icons, dual-state color; rail/action/logo all
      match a single accent.
- [x] **Button sizing & placement**: Primary Start/Save fixed 44px min-height,
      9/20px padding; danger/ghost consistent; actions right-aligned.
- [x] **Color consistency**: semantic colors (danger/warning/success/info) via
      palette helpers everywhere; severity colors match the HTML report.
- [x] **Empty states**: now present on Overview (recent targets) and History
      (list pane) — see §3.
- [x] **Loading states**: Scanner Running (progress, ETA, logs).
- [x] **Error states**: new inline error banner on scan failure (see §3).
- [x] **Success states**: COMPLETED pill + green status; scan-finished toast.
- [x] **Progress indicators**: QProgressBar + elapsed + estimated remaining.
- [x] **Keyboard navigation**: rail uses `QToolButton` checkable + tooltips;
      focus order follows layout; new visible focus rings (see §3).
- [x] **Accessibility**: accessible names on rail navigation; `#title/#subtitle`
      label properties; high-contrast colours in both themes.
- [x] **Window resizing**: min 1024×680; all pages wrapped in `QScrollArea`;
      split/stretch adapt; toast now repositions on resize (see §3).
- [x] **High-DPI scaling**: Fusion style + vector-drawn icons scale; QSS uses
      effective low/uppercase CSS px (Qt scales automatically).
- [x] **Responsiveness**: content reflows to scroll at narrow widths; no
      horizontal overflow in default windows.
- [x] **Theme consistency (Dark/Light)**: palettes fully threaded via
      `apply_palette` (fixed in v4.13.0); verified toggle switch, log views,
      risk meter, KPI icons.
- [x] **Micro-interactions**: hover states on all buttons/cards/menu items;
      toast fade; spinner on running state.
- [x] **Navigation flow**: left rail = single source of truth; new-scan flow;
      header pills communicate live status.
- [x] **No duplicate / unnecessary information**: header pill + status bar are
      distinct (live state vs. context); dead `scan_page.py` removed.

**Minor, non-blocking observations (not fixed — informational):**
- The header `READY/SCANNING/COMPLETED` pill and the status-bar message both
  describe scan state; intentional redundancy (at-a-glance in two regions).
- QSS hover state is instantaneous (Qt has no layout-independent transition);
  acceptable for tooling-quality.
- PDF preview is not yet a native pane (reports open in OS default app).

---

## 3. Issues Found & Fixed

| # | Category | Issue | Fix |
|---|----------|-------|-----|
| 1 | Loading/Errors | **Toasts anchored top-left**, overlapping the content area, instead of the intended bottom-right corner. | Toast host now repositions to the bottom-right (18px margin) in `resizeEvent (`MainWindow._reposition_toast_host`). Verified: toast at x=922,y=740 in a 1280×820 window. |
| 2 | Errors | **Scan failure was only a transient toast**; the setup page shown after failure gave no persistent feedback, so a user could miss why the scan ended. | Added an inline `errorBanner` (danger tones) on the Scanner setup page, shown with the failure/cancellation message and cleared on the next run. Verified shown/cleared. |
| 3 | States | **History list was a bare empty box** when no scans existed (no guidance). | Empty-state label ("No scans recorded yet. Run your first scan…") replaces the list pane when empty; list returns when scans exist. Verified. |
| 4 | States | **Overview "Recent Targets" was an empty list** with no call to action. | Empty-state message ("No targets scanned yet. Start a scan…") shown in place of the list when empty. Verified. |
| 5 | Accessibility | Global `outline: none` removed **all keyboard focus indicators**. | Added explicit `:focus` focus borders for push buttons, primary button, header button, rail button; removed the blanket rule. |
| 6 | Accessibility | Rail navigation (icons only) had no accessible names. | Added `setAccessibleName(label)` to each rail button. Verified. |
| 7 | Theme / branding | No **application window icon** was set (generic OS icon in taskbar/title bar). | Association: `MainWindow.setWindowIcon(icon_logo(32))`. Verified. |
| 8 | Startup | **Light theme did not propagate** to pages at launch (risk meter, KPI icons, brand logo, toggles kept `DARK` defaults until a theme change). | `_apply_palette_to_pages(palette)` now runs once after `apply_theme` in `__init__`. Verified. |
| 9 | Code cleanliness | Dead `MainWindow._quick_scan` method (unreferenced). | Removed. |
| 10 | Code cleanliness | `SectionCard.set_subtitle` was a **no-op `pass`** while the class accepts a subtitle. | Implemented dynamic subtitle label (reusable value). |
| 11 | Focus | `primaryButton:focus` had no visible focus (only hover). | Added a dedicated focus ring for the primary button. |

Deliberate non-change: the engine, scanners, HTML markup and assessment code
were untouched (verified by gates + the HTML-report escaping contract).

---

## 4. Improvements Summary

- **Bottom-right toasts** with correct resize behavior.
- **Persistent, themed inline error state** on scan failure / cancellation.
- **Empty-state guidance** on Overview and History.
- **Keyboard focus rings** restored and extended to all interactive control
  classes.
- **Accessible names** on navigation.
- **Window brand icon** for the OS/taskbar.
- **Correct light-theme startup** everywhere.
- Dead code removed; `set_subtitle` made functional.

---

## 5. Before / After

All 10 views (Overview, Scanner setup/running/completed, History, Settings,
About; dark + light) were captured before and after the polish:

- Before (v4.13.0 baseline): `reports/screenshots/gui/before/*.png`
- After (this pass): `reports/screenshots/gui/after/*.png`

Programmatic pixel-delta confirms the After renders differ only where intended
(toast placement, banners, empty guidance) and both themes remain distinct.

---

## 6. Regression Report

- **Validation**: `0 errors / 0 warnings`
- **Engine tests**: `0 errors / 0 warnings`
- **`test_validation.py`**: `0 errors / 0 warnings`
- **Regression**: `REGRESSION=0` (PASS=10, WARNING=6 — unchanged baseline)
- **Parity**: `PARITY=0` (byte-identical to frozen baseline)
- **Engine HTML**: unchanged (external invite, not in regression scope)

No architectural or engine change. GUI remains presentation-only (engine
imports confined to `gui/services/scan_worker.py`).