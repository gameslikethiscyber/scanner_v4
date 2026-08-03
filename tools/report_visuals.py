"""Render sample HTML reports to screenshots + print PDF (Playwright/Chromium).

Presentation-only tooling for the professional HTML report redesign. Produces:
  - full-page PNG per theme (light / dark) for the given report file
  - a print-preview PDF (A4) simulating "Print / Save as PDF"

Usage:
    python tools/report_visuals.py <report.html> --out <dir> [--no-pdf]
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from playwright.sync_api import sync_playwright


def shoot(html_path, out_dir, name, widths=(1440, 390), make_pdf=True):
    os.makedirs(out_dir, exist_ok=True)
    file_uri = "file:///" + os.path.abspath(html_path).replace("\\", "/")
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:
            print(f"[ERR] chromium launch failed: {e}")
            print("      run: playwright install chromium")
            return
        page = browser.new_page(viewport={"width": 1440, "height": 900},
                                device_scale_factor=1.5)
        page.goto(file_uri, wait_until="networkidle")
        page.wait_for_timeout(400)

        for theme in ("light", "dark"):
            page.evaluate(
                """(t) => { const root = document.documentElement;
                    root.dataset.theme = t;
                    const ev = new Event('themechange');
                    root.dispatchEvent(ev);
                }""", theme)
            page.wait_for_timeout(250)
            for w in widths:
                page.set_viewport_size({"width": w, "height": 900})
                page.wait_for_timeout(200)
                fname = f"{name}_{theme}_{w}px.png"
                page.screenshot(path=os.path.join(out_dir, fname),
                                full_page=True)
                print(f"[OK] {fname}")

        if make_pdf:
            page.set_viewport_size({"width": 1440, "height": 900})
            page.evaluate(
                """() => { const root = document.documentElement;
                    root.dataset.theme = 'light';
                }""")
            page.wait_for_timeout(200)
            pdf = os.path.join(out_dir, f"{name}_print.pdf")
            page.pdf(path=pdf, format="A4", print_background=True,
                     margin={"top": "10mm", "bottom": "10mm",
                             "left": "10mm", "right": "10mm"})
            print(f"[OK] {pdf}")
        browser.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("html")
    ap.add_argument("--out", default="reports/screenshots")
    ap.add_argument("--no-pdf", action="store_true")
    ap.add_argument("--name", default=None)
    args = ap.parse_args()
    base = args.name or os.path.splitext(os.path.basename(args.html))[0]
    shoot(args.html, args.out, base, make_pdf=not args.no_pdf)


if __name__ == "__main__":
    main()
