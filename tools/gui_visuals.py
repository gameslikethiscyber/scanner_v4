"""
GUI smoke + screenshot capture (headless, offscreen platform).

Renders every page in dark and light themes, seeds a throwaway scan history in
a temp AppData dir, and writes PNG screenshots to reports/screenshots/gui/. A
programmatic check verifies theme propagation and that no page throws.

Run:  python tools/gui_visuals.py
"""

import json
import os
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

OUT_DIR = os.path.join(ROOT, "reports", "screenshots", "gui")

SAMPLE_HISTORY = [
    {
        "target": "https://corp-portal.example.com",
        "started": "2026-08-02T14:22:10",
        "duration": 84.2,
        "mode": "deep",
        "risk_score": 78,
        "overall_severity": "High",
        "overall_color": "#F76B15",
        "overall_tier": "high",
        "report_paths": [os.path.join(ROOT, "reports", "samples", "mixed_corpus.html")],
        "vulnerabilities": 4,
        "coverage": 92,
        "requests_sent": 1240,
        "pages_crawled": 38,
        "confidence": 96,
        "modules_completed": 19,
        "findings": [
            {"severity": "critical", "status": "fail", "module": "SQL Injection",
             "confidence": 97, "title": "Error-based SQL injection in /search?id=",
             "target": "https://corp-portal.example.com/search?id=1"},
            {"severity": "high", "status": "fail", "module": "XSS",
             "confidence": 91, "title": "Reflected XSS in /search?q=",
             "target": "https://corp-portal.example.com/search?q=x"},
            {"severity": "medium", "status": "warning", "module": "Headers",
             "confidence": 88, "title": "Missing Content-Security-Policy",
             "target": "https://corp-portal.example.com"},
            {"severity": "low", "status": "warning", "module": "Cookies",
             "confidence": 82, "title": "Session cookie missing Secure flag",
             "target": "https://corp-portal.example.com"},
        ],
    },
    {
        "target": "https://dev-api.example.com",
        "started": "2026-08-01T09:05:44",
        "duration": 41.5,
        "mode": "standard",
        "risk_score": 34,
        "overall_severity": "Medium",
        "overall_color": "#F5A623",
        "overall_tier": "medium",
        "report_paths": [],
        "vulnerabilities": 2,
        "coverage": 61,
        "requests_sent": 520,
        "pages_crawled": 14,
        "confidence": 89,
        "modules_completed": 19,
        "findings": [],
    },
    {
        "target": "https://docs.example.com",
        "started": "2026-07-30T16:48:02",
        "duration": 12.7,
        "mode": "quick",
        "risk_score": 8,
        "overall_severity": "Low",
        "overall_color": "#2E9E5B",
        "overall_tier": "low",
        "report_paths": [],
        "vulnerabilities": 1,
        "coverage": 47,
        "requests_sent": 96,
        "pages_crawled": 5,
        "confidence": 84,
        "modules_completed": 19,
        "findings": [],
    },
]


def _seed_appdata() -> str:
    tmp = tempfile.mkdtemp(prefix="sea_gui_")
    os.makedirs(os.path.join(tmp, "SEACorporateScanner"), exist_ok=True)
    with open(os.path.join(tmp, "SEACorporateScanner", "history.json"),
              "w", encoding="utf-8") as fh:
        json.dump({"scans": SAMPLE_HISTORY}, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(tmp, "SEACorporateScanner", "settings.json"),
              "w", encoding="utf-8") as fh:
        json.dump({"theme": "dark", "default_scan_mode": "standard"}, fh,
                  ensure_ascii=False, indent=2)
    return tmp


def _grab(widget, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    widget.grab().save(path, "PNG")
    print(f"  saved {os.path.relpath(path, ROOT)}")


def main() -> int:
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtWidgets import QApplication

    appdata = _seed_appdata()
    os.environ["APPDATA"] = appdata

    from gui.main_window import MainWindow
    from gui.resources.styles import apply_theme
    from gui.services.settings_store import SettingsStore

    app = QApplication(sys.argv)
    app.setApplicationName("SEA Corporate Security Scanner")

    checks = []

    for theme in ("dark", "light"):
        print(f"\n=== theme: {theme} ===")
        palette = apply_theme(app, theme)
        store = SettingsStore()
        store.set("theme", theme)
        window = MainWindow(store)
        window.show()
        window._apply_palette_to_pages(palette)
        app.processEvents()

        # --- overview ---
        window.navigate("overview")
        app.processEvents()
        _grab(window, os.path.join(OUT_DIR, f"{theme}_overview.png"))
        checks.append(("overview palette", window.overview_page._palette is palette))

        # --- scanner setup ---
        window.navigate("scanner")
        app.processEvents()
        _grab(window, os.path.join(OUT_DIR, f"{theme}_scanner_setup.png"))

        # --- scanner running ---
        window.scanner_page._set_state(window.scanner_page.STATE_RUNNING)
        window.scanner_page.progress_bar.setValue(62)
        window.scanner_page.stage_label.setText("Scanning module 11/19 — Cross-Site Scripting")
        window.scanner_page._running_logs.append_log("info", "Scan started: https://corp-portal.example.com (deep)")
        window.scanner_page._running_logs.append_log("debug", "Crawled 38 pages")
        window.scanner_page._running_logs.append_log("warning", "Session cookie missing Secure flag")
        window.scanner_page._running_logs.append_log("error", "TLS certificate expires in 9 days")
        app.processEvents()
        _grab(window, os.path.join(OUT_DIR, f"{theme}_scanner_running.png"))

        # --- scanner completed ---
        summary = dict(SAMPLE_HISTORY[0])
        window.scanner_page.on_scan_finished(summary)
        app.processEvents()
        _grab(window, os.path.join(OUT_DIR, f"{theme}_scanner_completed.png"))
        checks.append(("scanner log palette", window.scanner_page._running_logs._palette is palette))

        # --- history ---
        window.navigate("history")
        app.processEvents()
        _grab(window, os.path.join(OUT_DIR, f"{theme}_history.png"))
        checks.append(("history palette", window.history_page._palette is palette))

        # --- settings ---
        window.navigate("settings")
        app.processEvents()
        _grab(window, os.path.join(OUT_DIR, f"{theme}_settings.png"))
        checks.append(("settings toggles palette",
                       all(t._palette is palette for t in window.settings_page._toggles)))

        # --- about ---
        window.navigate("about")
        app.processEvents()
        _grab(window, os.path.join(OUT_DIR, f"{theme}_about.png"))

        window.close()

    failed = [name for name, ok in checks if not ok]
    print("\n=== checks ===")
    for name, ok in checks:
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")
    if failed:
        print(f"FAILED: {failed}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
