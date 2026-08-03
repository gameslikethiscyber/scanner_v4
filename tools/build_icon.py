"""
Build a multi-size Windows .ico and a high-res .png from the programmatic
GUI logo (gui/resources/icons.icon_logo). Used by the packaging pipeline.

Usage: python tools/build_icon.py --out dist_assets/app
"""
import argparse
import os
import struct
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
APP = QApplication = None


def _emit_logo_pixmap(size):
    from PySide6.QtGui import QColor
    from gui.resources import icons

    icon = icons.icon_logo(size, QColor("#4F46E5"))
    return icon.pixmap(size, size)


def _png_bytes(pm):
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice

    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    pm.save(buf, "PNG")
    return bytes(buf.data())


def make_ico(pngs):
    header = struct.pack("<HHH", 0, 1, len(pngs))
    entries = b""
    data = b""
    base = 6 + 16 * len(pngs)
    for size in SIZES:
        raw = pngs[size]
        b = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", b, b, 0, 0, 1, 32, len(raw), base + len(data))
        data += raw
    return header + entries + data


def main():
    from PySide6.QtWidgets import QApplication

    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dist_assets/app")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    app = QApplication([])
    pngs = {}
    for size in SIZES:
        pngs[size] = _png_bytes(_emit_logo_pixmap(size))

    with open(os.path.join(args.out, "app.ico"), "wb") as f:
        f.write(make_ico(pngs))
    with open(os.path.join(args.out, "app_256.png"), "wb") as f:
        f.write(pngs[256])
    print("wrote", os.path.join(args.out, "app.ico"), os.path.join(args.out, "app_256.png"))


if __name__ == "__main__":
    main()