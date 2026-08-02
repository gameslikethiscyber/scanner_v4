"""
ToastHost — transient notifications stacked in the bottom-right corner.
Auto-expire; themed for success / warning / danger / info.
"""

from PySide6.QtCore import Qt, QPropertyAnimation, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from gui.resources.styles import DARK, Palette


class _Toast(QFrame):
    LEVEL_COLOR = {
        "success": "success",
        "warning": "warning",
        "danger": "danger",
        "info": "info",
    }

    def __init__(self, title: str, body: str, level: str, duration_ms: int, host):
        super().__init__(host)
        self.setObjectName("toast")
        self.setFixedWidth(320)
        self._host = host
        self._fade = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade.setDuration(220)
        self._fade.finished.connect(self._on_fade_done)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(10)

        color_name = self.LEVEL_COLOR.get(level, "info")
        color = getattr(host.palette, color_name, "#38bdf8")

        badge = QLabel()
        badge.setFixedSize(10, 10)
        badge.setStyleSheet(
            f"background-color: {color}; border-radius: 5px;")
        layout.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)

        text_col = QVBoxLayout()
        text_col.setSpacing(1)
        title_label = QLabel(title)
        title_label.setObjectName("toastTitle")
        text_col.addWidget(title_label)
        if body:
            body_label = QLabel(body)
            body_label.setObjectName("toastBody")
            body_label.setWordWrap(True)
            text_col.addWidget(body_label)
        layout.addLayout(text_col, 1)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.close)
        self._timer.start(max(1500, duration_ms))

    def closeEvent(self, event) -> None:
        self._fade.stop()
        self._fade.setStartValue(self.windowOpacity())
        self._fade.setEndValue(0.0)
        self._fade.start()
        event.accept()

    def _on_fade_done(self) -> None:
        self.hide()
        self.deleteLater()
        self._host._prune()


class ToastHost(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.palette = DARK
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(8)
        self._layout.addStretch(1)
        self.setFixedWidth(340)
        self.hide()

    def apply_palette(self, palette: Palette) -> None:
        self.palette = palette

    def show_toast(self, title: str, body: str = "", level: str = "info",
                   duration_ms: int = 4200) -> None:
        toast = _Toast(title, body, level, duration_ms, self)
        self._layout.insertWidget(self._layout.count() - 1, toast)
        toast.show()
        self.show()
        self.raise_()

    def _prune(self) -> None:
        pass
