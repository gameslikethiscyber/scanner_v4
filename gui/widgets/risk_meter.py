"""
RiskMeter — the big risk-score readout with tier colouring and a segmented
scale bar under it.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
)

from gui.resources.styles import DARK, Palette, tier_color


class RiskMeter(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("riskMeter")
        self._palette = DARK

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(14)
        top.addStretch(1)

        right = QVBoxLayout()
        right.setSpacing(2)
        right.setAlignment(Qt.AlignmentFlag.AlignRight)

        self._tier_label = QLabel("NO RISK")
        self._tier_label.setObjectName("riskTier")
        self._tier_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        right.addWidget(self._tier_label)

        self._sub_label = QLabel("—")
        self._sub_label.setObjectName("riskSub")
        self._sub_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        right.addWidget(self._sub_label)

        self._score_label = QLabel("—")
        self._score_label.setObjectName("riskScore")
        self._score_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        top.addLayout(right)
        layout.addLayout(top)

        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(8)
        layout.addWidget(self._bar)

        scale = QHBoxLayout()
        scale.setSpacing(0)
        for label in ("0", "25", "50", "75", "100"):
            lbl = QLabel(label)
            lbl.setProperty("muted", True)
            lbl.setProperty("small", True)
            scale.addWidget(lbl)
            scale.addStretch(1)
        scale.setStretch(scale.count() - 1, 0)
        layout.addLayout(scale)

    def set_risk(self, score: float, tier: str, description: str = "") -> None:
        palette = self._palette
        color = tier_color(tier, palette)
        self._score_label.setText(f"{int(score)}%")
        self._score_label.setStyleSheet(f"color: {color};")
        self._tier_label.setText((tier or "none").upper())
        self._tier_label.setStyleSheet(f"color: {color};")
        self._sub_label.setText(description or f"Risk score · {int(score)}/100")
        self._bar.setValue(int(score))
        self._bar.setProperty("danger", str(tier in ("critical", "high", "medium")).lower())
        self._bar.style().unpolish(self._bar)
        self._bar.style().polish(self._bar)

    def reset(self) -> None:
        palette = self._palette
        self._score_label.setText("—")
        self._score_label.setStyleSheet("")
        self._tier_label.setText("NO RISK")
        self._tier_label.setStyleSheet("")
        self._sub_label.setText("No scan data yet")
        self._bar.setValue(0)

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
