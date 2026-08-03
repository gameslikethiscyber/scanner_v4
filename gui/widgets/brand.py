"""
BrandHeader — the SEA logo mark plus product name / version block.
"""

from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from gui.resources.styles import DARK, Palette
from gui.version import APP_NAME, GUI_VERSION


class BrandHeader(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._palette = DARK
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        from gui.resources import icons

        self.mark = QLabel()
        self.mark.setFixedSize(34, 34)
        layout.addWidget(self.mark)

        block = QVBoxLayout()
        block.setSpacing(0)
        name = QLabel(APP_NAME)
        name.setObjectName("brandMark")
        block.addWidget(name)
        sub = QLabel(f"v{GUI_VERSION}")
        sub.setObjectName("brandSub")
        block.addWidget(sub)
        layout.addLayout(block)
        layout.addStretch(1)

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        from gui.resources import icons
        self.mark.setPixmap(icons.icon_logo(34, palette.accent).pixmap(34, 34))
