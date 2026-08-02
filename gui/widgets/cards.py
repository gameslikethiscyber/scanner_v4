"""
Card components: KPI metric card, generic panel card, and section header.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from gui.resources.styles import DARK, Palette, qcolor


class SectionCard(QWidget):
    """Kicker + title + optional subtitle used at the top of every page."""

    def __init__(self, kicker: str, title: str, subtitle: str = "", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)
        if kicker:
            k = QLabel(kicker.upper())
            k.setProperty("kicker", True)
            layout.addWidget(k)
        title_label = QLabel(title)
        title_label.setProperty("title", True)
        layout.addWidget(title_label)
        if subtitle:
            sub = QLabel(subtitle)
            sub.setProperty("subtitle", True)
            sub.setWordWrap(True)
            layout.addWidget(sub)

    def set_subtitle(self, text: str) -> None:
        pass


class KpiCard(QFrame):
    """A large-value metric card with an icon, title and caption."""

    def __init__(self, title: str, value: str = "—", caption: str = "",
                 icon=None, accent: str = None, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self._palette = DARK
        self._accent = accent

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(10)
        self._icon_label = QLabel()
        if icon is not None:
            self._icon_label.setPixmap(icon.pixmap(20, 20))
        top.addWidget(self._icon_label)
        top.addStretch(1)

        self._title_label = QLabel(title.upper())
        self._title_label.setProperty("kicker", True)
        top.addWidget(self._title_label, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(top)

        self._value_label = QLabel(value)
        self._value_label.setObjectName("kpiValue")
        layout.addWidget(self._value_label)

        self._caption_label = QLabel(caption)
        self._caption_label.setObjectName("kpiCaption")
        self._caption_label.setWordWrap(True)
        layout.addWidget(self._caption_label)

    def set_value(self, value: str) -> None:
        self._value_label.setText(value)

    def set_caption(self, caption: str) -> None:
        self._caption_label.setText(caption)
        self._caption_label.setVisible(bool(caption))

    def set_accent(self, color: str | None) -> None:
        self._accent = color
        if color:
            self._value_label.setStyleSheet(f"color: {color};")

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        if self._accent:
            self._value_label.setStyleSheet(f"color: {self._accent};")
        else:
            self._value_label.setStyleSheet("")


class PanelCard(QFrame):
    """A titled container with a header row and a body widget."""

    def __init__(self, title: str, subtitle: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        header = QVBoxLayout()
        header.setSpacing(2)
        title_label = QLabel(title)
        title_label.setObjectName("cardTitle")
        header.addWidget(title_label)
        if subtitle:
            sub = QLabel(subtitle)
            sub.setObjectName("cardSub")
            sub.setWordWrap(True)
            header.addWidget(sub)
        layout.addLayout(header)

        self._body = QWidget()
        self._body_layout = QVBoxLayout(self._body)
        self._body_layout.setContentsMargins(0, 0, 0, 0)
        self._body_layout.setSpacing(10)
        layout.addWidget(self._body, 1)

    def body(self) -> QVBoxLayout:
        return self._body_layout
