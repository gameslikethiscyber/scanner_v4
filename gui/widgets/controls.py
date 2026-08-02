"""
Custom controls: a segmented button group and a painted toggle switch.
"""

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QAbstractButton,
    QFrame,
    QHBoxLayout,
    QPushButton,
    QSizePolicy,
)

from gui.resources.styles import DARK, Palette


class SegmentedControl(QFrame):
    """A pill group of mutually exclusive options (mode / theme picker)."""

    currentChanged = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("segmented")
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(4, 4, 4, 4)
        self._layout.setSpacing(4)
        self._buttons = []
        self._data = []

    def add_option(self, label: str, value: str, tooltip: str = "") -> None:
        btn = QPushButton(label)
        btn.setObjectName("segmentButton")
        btn.setCheckable(True)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        if tooltip:
            btn.setToolTip(tooltip)
        btn.clicked.connect(lambda _checked=False, v=value: self.set_current(v))
        self._layout.addWidget(btn)
        self._buttons.append(btn)
        self._data.append(value)

    def set_current(self, value: str) -> None:
        if value not in self._data:
            return
        for btn, data in zip(self._buttons, self._data):
            btn.setChecked(data == value)
        self.currentChanged.emit(value)

    def current_value(self) -> str | None:
        for btn, data in zip(self._buttons, self._data):
            if btn.isChecked():
                return data
        return self._data[0] if self._data else None


class ToggleSwitch(QAbstractButton):
    """A compact on/off switch painted in the current theme."""

    toggledChanged = Signal(bool)

    def __init__(self, parent=None, palette: Palette = DARK):
        super().__init__(parent)
        self._palette = palette
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(40, 22)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.toggled.connect(self.toggledChanged)

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette

    def sizeHint(self) -> QSize:
        return QSize(40, 22)

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pal = self._palette
        track_color = QColor(pal.accent) if self.isChecked() else QColor(pal.input)
        track_border = QColor(pal.border_strong) if not self.isChecked() else QColor(pal.accent)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(track_color)
        rect = self.rect().adjusted(1, 1, -1, -1)
        p.drawRoundedRect(rect, rect.height() / 2, rect.height() / 2)

        border = QColor(pal.border)
        if not self.isChecked():
            pen = border
            p.setPen(pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(rect, rect.height() / 2, rect.height() / 2)

        knob_diameter = rect.height() - 4
        knob_x = rect.left() + 2 if not self.isChecked() else rect.right() - knob_diameter - 2
        knob_y = rect.top() + 2
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#ffffff") if self.isChecked() else QColor(pal.subtext))
        p.drawEllipse(knob_x, knob_y, knob_diameter, knob_diameter)
        p.end()
