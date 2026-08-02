"""
History page — master–detail over real scan history. Selecting an entry shows
its recorded summary in the shared SummaryView; no fabricated fields.
"""

import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from gui.resources import icons
from gui.resources.styles import DARK, Palette, tier_from_severity
from gui.widgets.cards import SectionCard
from gui.widgets.summary import SummaryView


def _format_dt(iso_value: str) -> str:
    if not iso_value:
        return "—"
    try:
        return iso_value.replace("T", " ")[:16]
    except Exception:
        return str(iso_value)


def _entry_to_summary(entry: dict) -> dict:
    """Adapt a history entry (subset of fields) into a summary-shaped dict."""
    return {
        "target": entry.get("target", ""),
        "mode": entry.get("mode", ""),
        "started": entry.get("started", ""),
        "duration": entry.get("duration", 0),
        "risk_score": entry.get("risk_score", 0),
        "overall_severity": entry.get("overall_severity", "No Risk"),
        "overall_color": entry.get("overall_color", "#38bdf8"),
        "overall_tier": entry.get("overall_tier")
                      or tier_from_severity(entry.get("overall_severity", "")),
        "overall_description": "",
        "confidence": entry.get("confidence"),
        "modules_completed": entry.get("modules_completed"),
        "coverage": entry.get("coverage"),
        "vulnerabilities": entry.get("vulnerabilities", 0),
        "requests_sent": entry.get("requests_sent"),
        "pages_crawled": entry.get("pages_crawled"),
        "report_paths": entry.get("report_paths", []),
        "findings": [],
    }


class HistoryPage(QWidget):
    new_scan_requested = Signal()

    def __init__(self, history_store, parent=None):
        super().__init__(parent)
        self.history_store = history_store
        self._palette = DARK
        self._selected_index = None

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(32, 28, 32, 28)
        body_layout.setSpacing(18)

        body_layout.addWidget(SectionCard(
            "History",
            "Past Scans",
            "Every completed scan, stored locally. Select an entry to inspect it.",
        ))

        split = QHBoxLayout()
        split.setSpacing(16)

        self._list = QListWidget()
        self._list.setMinimumWidth(340)
        self._list.setMaximumWidth(420)
        self._list.currentRowChanged.connect(self._on_selection_changed)
        split.addWidget(self._list)

        self.summary_view = SummaryView()
        split.addWidget(self.summary_view, 1)
        body_layout.addLayout(split, 1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(body)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(scroll)

        self.refresh()

    # -------------------------------------------------------------- refresh
    def refresh(self) -> None:
        scans = self.history_store.get_all()
        previous = self._selected_index
        self._list.blockSignals(True)
        self._list.clear()
        for entry in reversed(scans):
            target = entry.get("target", "unknown")
            started = _format_dt(entry.get("started", ""))
            severity = entry.get("overall_severity", "")
            item = QListWidgetItem(f"{target}\n{started}")
            item.setData(Qt.ItemDataRole.UserRole, entry)
            item.setToolTip(
                f"{severity} · {entry.get('mode', '')} · "
                f"{entry.get('duration', 0):.1f}s")
            self._list.addItem(item)
        self._list.blockSignals(False)

        if self._list.count() > 0:
            target_row = min(previous or 0, self._list.count() - 1)
            self._list.setCurrentRow(target_row)
        else:
            self.summary_view.clear_results()

    def _on_selection_changed(self, row: int) -> None:
        self._selected_index = row
        item = self._list.item(row)
        if item is None:
            return
        entry = item.data(Qt.ItemDataRole.UserRole)
        if entry:
            self.summary_view.display_summary(_entry_to_summary(entry))

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.summary_view.apply_palette(palette)
