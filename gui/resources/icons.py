"""
Programmatic stroke icons — drawn with QPainter so the app needs no binary
assets. Dual-state by colour: pass the idle colour (rail icons) or the active
colour (accent) at call time.

All functions return a QIcon sized for the requested pixel size.
"""

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)

_LIGHT_SUBTEXT = "#93a0b5"
_LIGHT_ACCENT = "#2e7cf6"


def _make(size: int, color: str, painter_fn):
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter_fn(p, size, QColor(color))
    p.end()
    return QIcon(pm)


def _stroke(p, color, width):
    pen = QPen(color, width)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    return pen


def _fill_round(p, x, y, w, h, r, color):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(color))
    p.drawRoundedRect(QRectF(x, y, w, h), r, r)


# --------------------------------------------------------------------------- #
# Rail icons — stroke style, dual-state through the colour argument.
# --------------------------------------------------------------------------- #
def icon_overview(size=20, color=_LIGHT_SUBTEXT):
    """Four-pane dashboard grid."""
    def fn(p, s, c):
        w = max(1.4, s / 13)
        _stroke(p, c, w)
        cell = (s - 5) / 2
        for i in range(2):
            for j in range(2):
                p.drawRoundedRect(QRectF(2 + j * (cell + 1), 2 + i * (cell + 1), cell, cell), 2, 2)
    return _make(size, color, fn)


def icon_scanner(size=20, color=_LIGHT_SUBTEXT):
    """Crosshair / target reticle."""
    def fn(p, s, c):
        w = max(1.6, s / 11)
        _stroke(p, c, w)
        cx, cy = s / 2, s / 2
        p.drawEllipse(QPointF(cx, cy), s * 0.36, s * 0.36)
        p.drawEllipse(QPointF(cx, cy), s * 0.13, s * 0.13)
        p.drawLine(QPointF(cx, 1), QPointF(cx, s * 0.2))
        p.drawLine(QPointF(cx, s * 0.8), QPointF(cx, s - 1))
        p.drawLine(QPointF(1, cy), QPointF(s * 0.2, cy))
        p.drawLine(QPointF(s * 0.8, cy), QPointF(s - 1, cy))
    return _make(size, color, fn)


def icon_history(size=20, color=_LIGHT_SUBTEXT):
    """Clock with a counter-clockwise arrow."""
    def fn(p, s, c):
        w = max(1.6, s / 11)
        _stroke(p, c, w)
        p.drawArc(QRectF(2, 2, s - 4, s - 4), 30 * 16, 300 * 16)
        p.drawArc(QRectF(2, 2, s - 4, s - 4), 0, 30 * 16)
        p.drawLine(QPointF(s / 2, s / 2), QPointF(s / 2, s * 0.3))
        p.drawLine(QPointF(s / 2, s / 2), QPointF(s * 0.7, s / 2))
        p.drawPolyline([
            QPointF(s - 1.5, s * 0.16),
            QPointF(s - 5.5, s * 0.16),
            QPointF(s - 5.5, s * 0.52),
        ])
    return _make(size, color, fn)


def icon_settings(size=20, color=_LIGHT_SUBTEXT):
    """Three horizontal sliders."""
    def fn(p, s, c):
        w = max(1.6, s / 11)
        _stroke(p, c, w)
        for i in range(3):
            y = 4 + i * (s - 8) / 2
            p.drawLine(QPointF(2, y), QPointF(s - 2, y))
            dot = QPointF(s * (0.28 if i % 2 == 0 else 0.62), y)
            p.setBrush(QBrush(c))
            p.drawEllipse(dot, 2.2, 2.2)
            p.setBrush(Qt.BrushStyle.NoBrush)
    return _make(size, color, fn)


def icon_about(size=20, color=_LIGHT_SUBTEXT):
    """Info circle."""
    def fn(p, s, c):
        w = max(1.6, s / 11)
        _stroke(p, c, w)
        p.drawEllipse(QRectF(2, 2, s - 4, s - 4))
        p.drawLine(QPointF(s / 2, s * 0.42), QPointF(s / 2, s * 0.7))
        p.drawLine(QPointF(s / 2, s * 0.3), QPointF(s / 2, s * 0.34))
    return _make(size, color, fn)


# --------------------------------------------------------------------------- #
# Action icons
# --------------------------------------------------------------------------- #
def icon_play(size=18, color="#ffffff"):
    def fn(p, s, c):
        path = QPainterPath()
        path.moveTo(s * 0.22, 1.5)
        path.lineTo(s * 0.88, s / 2)
        path.lineTo(s * 0.22, s - 1.5)
        path.closeSubpath()
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor(c)))
        p.drawPath(path)
    return _make(size, color, fn)


def icon_stop(size=18, color=_LIGHT_ACCENT):
    def fn(p, s, c):
        _fill_round(p, 2, 2, s - 4, s - 4, 3, c)
    return _make(size, color, fn)


def icon_cancel(size=18, color=_LIGHT_SUBTEXT):
    def fn(p, s, c):
        w = max(1.6, s / 11)
        _stroke(p, c, w)
        p.drawEllipse(QRectF(2, 2, s - 4, s - 4))
        p.drawLine(QPointF(s * 0.32, s * 0.32), QPointF(s * 0.68, s * 0.68))
        p.drawLine(QPointF(s * 0.68, s * 0.32), QPointF(s * 0.32, s * 0.68))
    return _make(size, color, fn)


def icon_plus(size=18, color="#ffffff"):
    def fn(p, s, c):
        w = max(1.8, s / 9)
        _stroke(p, c, w)
        p.drawLine(QPointF(s / 2, s * 0.18), QPointF(s / 2, s * 0.82))
        p.drawLine(QPointF(s * 0.18, s / 2), QPointF(s * 0.82, s / 2))
    return _make(size, color, fn)


def icon_folder(size=16, color=_LIGHT_SUBTEXT):
    def fn(p, s, c):
        w = max(1.3, s / 12)
        _stroke(p, c, w)
        p.drawRoundedRect(QRectF(1.5, s * 0.32, s - 3, s * 0.52), 2, 2)
        p.drawLine(QPointF(1.5, s * 0.36), QPointF(s * 0.4, s * 0.36))
        p.drawLine(QPointF(s * 0.4, s * 0.36), QPointF(s * 0.5, s * 0.46))
        p.drawLine(QPointF(s * 0.5, s * 0.46), QPointF(s - 1.5, s * 0.46))
    return _make(size, color, fn)


def icon_doc(size=16, color=_LIGHT_SUBTEXT):
    def fn(p, s, c):
        w = max(1.3, s / 12)
        _stroke(p, c, w)
        p.drawRoundedRect(QRectF(3, 1.5, s - 6, s - 3), 2, 2)
        for i in range(3):
            y = s * 0.3 + i * (s * 0.17)
            p.drawLine(QPointF(s * 0.3, y), QPointF(s * 0.7, y))
    return _make(size, color, fn)


def icon_save(size=16, color=_LIGHT_SUBTEXT):
    def fn(p, s, c):
        w = max(1.3, s / 12)
        _stroke(p, c, w)
        p.drawRoundedRect(QRectF(2, 2, s - 4, s - 4), 2, 2)
        p.drawLine(QPointF(4.5, 2.5), QPointF(4.5, s / 2 - 1))
        p.drawLine(QPointF(4.5, s / 2 - 1), QPointF(s - 4.5, s / 2 - 1))
        p.drawLine(QPointF(s - 4.5, s / 2 - 1), QPointF(s - 4.5, s - 2))
        p.drawRoundedRect(QRectF(s * 0.3, s * 0.55, s * 0.4, s * 0.3), 1.5, 1.5)
    return _make(size, color, fn)


def icon_clear(size=16, color=_LIGHT_SUBTEXT):
    def fn(p, s, c):
        w = max(1.3, s / 12)
        _stroke(p, c, w)
        p.drawLine(QPointF(1.5, 1.5), QPointF(s - 1.5, s - 1.5))
        p.drawLine(QPointF(s - 1.5, 1.5), QPointF(1.5, s - 1.5))
    return _make(size, color, fn)


def icon_external(size=16, color=_LIGHT_SUBTEXT):
    def fn(p, s, c):
        w = max(1.4, s / 11)
        _stroke(p, c, w)
        p.drawLine(QPointF(s * 0.22, s * 0.22), QPointF(s * 0.74, s * 0.74))
        p.drawLine(QPointF(s * 0.28, s * 0.74), QPointF(s * 0.74, s * 0.74))
        p.drawLine(QPointF(s * 0.74, s * 0.74), QPointF(s * 0.74, s * 0.28))
        p.drawRoundedRect(QRectF(2, 2, s - 4, s - 4), 3, 3)
    return _make(size, color, fn)


def icon_refresh(size=16, color=_LIGHT_SUBTEXT):
    def fn(p, s, c):
        w = max(1.4, s / 11)
        _stroke(p, c, w)
        p.drawArc(QRectF(2.5, 2.5, s - 5, s - 5), 30 * 16, 300 * 16)
        p.drawLine(QPointF(s - 1.5, s * 0.2), QPointF(s - 5, s * 0.16))
        p.drawLine(QPointF(s - 1.5, s * 0.2), QPointF(s - 5.2, s * 0.34))
    return _make(size, color, fn)


def icon_alert(size=18, color="#f87171"):
    def fn(p, s, c):
        w = max(1.6, s / 11)
        _stroke(p, c, w)
        p.drawLine(QPointF(s / 2, 2), QPointF(s - 2, s - 2))
        p.drawLine(QPointF(s / 2, 2), QPointF(2, s - 2))
        p.drawLine(QPointF(2, s - 2), QPointF(s - 2, s - 2))
        p.drawLine(QPointF(s / 2, s * 0.42), QPointF(s / 2, s * 0.62))
        p.drawLine(QPointF(s / 2, s * 0.72), QPointF(s / 2, s * 0.75))
    return _make(size, color, fn)


# --------------------------------------------------------------------------- #
# Logo
# --------------------------------------------------------------------------- #
def icon_logo(size=48, color=_LIGHT_ACCENT):
    def fn(p, s, c):
        path = QPainterPath()
        path.moveTo(s / 2, 2)
        path.lineTo(s - 3, s * 0.2)
        path.lineTo(s - 3, s * 0.58)
        path.cubicTo(s - 3, s * 0.82, s * 0.78, s * 0.95, s / 2, s - 2)
        path.cubicTo(s * 0.22, s * 0.95, 3, s * 0.82, 3, s * 0.58)
        path.lineTo(3, s * 0.2)
        path.closeSubpath()
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor(c)))
        p.drawPath(path)
        pen = QPen(QColor("#ffffff"), max(2.0, s / 16))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawLine(QPointF(s * 0.34, s * 0.52), QPointF(s * 0.46, s * 0.64))
        p.drawLine(QPointF(s * 0.46, s * 0.64), QPointF(s * 0.68, s * 0.36))
    return _make(size, color, fn)


# Backwards-compatible aliases for code that still references the old names.
icon_dashboard = icon_overview
icon_results = icon_history
icon_quick = icon_scanner
icon_standard = icon_scanner
icon_deep = icon_scanner
