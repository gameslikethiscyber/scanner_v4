"""
Overview page — real state of the scanner: last scan risk readout, aggregate
KPIs from actual history, recent targets, and quick actions.
"""

import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from gui.resources import icons
from gui.resources.styles import DARK, Palette, tier_color
from gui.version import ENGINE_VERSION, GUI_VERSION
from gui.widgets.cards import KpiCard, PanelCard, SectionCard
from gui.widgets.risk_meter import RiskMeter


def _format_dt(iso_value: str) -> str:
    if not iso_value:
        return "—"
    try:
        return iso_value.replace("T", " ")[:16]
    except Exception:
        return str(iso_value)


class OverviewPage(QWidget):
    new_scan_requested = Signal()
    open_history_requested = Signal()
    open_latest_report = Signal()

    def __init__(self, settings_store, history_store, controller, parent=None):
        super().__init__(parent)
        self.settings_store = settings_store
        self.history_store = history_store
        self.controller = controller
        self._palette = DARK

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(32, 28, 32, 28)
        body_layout.setSpacing(18)

        body_layout.addWidget(SectionCard(
            "Overview",
            "Scan Intelligence",
            "A live view of the scanner's real state and past activity.",
        ))

        top = QHBoxLayout()
        top.setSpacing(16)
        self.risk_meter = RiskMeter()
        top.addWidget(self.risk_meter, 3)

        kpi_widget = QWidget()
        kpi_grid = QVBoxLayout(kpi_widget)
        kpi_grid.setContentsMargins(0, 0, 0, 0)
        kpi_grid.setSpacing(10)
        self._cards = {}
        for key, title, icon in (
            ("scans", "Total Scans", icons.icon_history),
            ("vulns", "Vulnerabilities", icons.icon_alert),
            ("coverage", "Coverage", icons.icon_doc),
            ("version", "Version", icons.icon_about),
        ):
            card = KpiCard(title, icon=icon())
            kpi_grid.addWidget(card)
            self._cards[key] = card
        top.addWidget(kpi_widget, 2)
        body_layout.addLayout(top)

        middle = QHBoxLayout()
        middle.setSpacing(16)

        recent_panel = PanelCard("Recent Targets", "Double-click a target to start a new scan")
        recent_panel.setMinimumWidth(360)
        self._recent_list = QListWidget()
        self._recent_list.itemDoubleClicked.connect(
            lambda _item: self.new_scan_requested.emit())
        recent_panel.body().addWidget(self._recent_list)
        middle.addWidget(recent_panel, 2)

        side = QVBoxLayout()
        side.setSpacing(16)

        last_panel = PanelCard("Last Scan", "The most recently completed scan")
        self._last_target_label = QLabel("No scans yet")
        self._last_target_label.setObjectName("cardSub")
        self._last_target_label.setWordWrap(True)
        last_panel.body().addWidget(self._last_target_label)
        self._last_time_label = QLabel("")
        self._last_time_label.setProperty("muted", True)
        self._last_time_label.setProperty("small", True)
        last_panel.body().addWidget(self._last_time_label)

        self._scan_state_pill = QLabel("READY")
        self._scan_state_pill.setObjectName("pill")
        self._scan_state_pill.setProperty("state", "idle")
        last_panel.body().addWidget(self._scan_state_pill)

        actions_panel = PanelCard("Quick Actions")
        self.new_scan_btn = QPushButton("New Scan")
        self.new_scan_btn.setObjectName("primaryButton")
        self.new_scan_btn.setIcon(icons.icon_plus())
        self.new_scan_btn.clicked.connect(self.new_scan_requested.emit)
        self.open_report_btn = QPushButton("Open Latest Report")
        self.open_report_btn.setIcon(icons.icon_doc())
        self.open_report_btn.clicked.connect(self.open_latest_report)
        self.open_history_btn = QPushButton("View History")
        self.open_history_btn.setIcon(icons.icon_history())
        self.open_history_btn.clicked.connect(self.open_history_requested)
        actions_panel.body().addWidget(self.new_scan_btn)
        actions_panel.body().addWidget(self.open_report_btn)
        actions_panel.body().addWidget(self.open_history_btn)

        side.addWidget(last_panel, 1)
        side.addWidget(actions_panel, 1)
        middle.addLayout(side, 1)
        body_layout.addLayout(middle, 1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(body)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(scroll)

    # -------------------------------------------------------------- refresh
    def refresh(self) -> None:
        history = self.history_store
        last = history.get_last()
        palette = self._palette

        if self.controller.running:
            self._scan_state_pill.setText("SCANNING")
            self._scan_state_pill.setProperty("state", "info")
        else:
            self._scan_state_pill.setText("READY")
            self._scan_state_pill.setProperty("state", "idle")
        self._restyle(self._scan_state_pill)

        self._cards["scans"].set_value(str(history.total_scans()))

        if last:
            self._cards["vulns"].set_value(str(last.get("vulnerabilities", 0)))
            self._cards["vulns"].set_caption(
                f"{last.get('mode', '')} · {last.get('duration', 0):.1f}s")
            self._cards["coverage"].set_value(f"{last.get('coverage', 0)}%")

            tier = last.get("overall_tier", "none")
            score = last.get("risk_score", 0)
            self.risk_meter.set_risk(score, tier, last.get("overall_severity", ""))

            self._last_target_label.setText(last.get("target", "—"))
            self._last_time_label.setText(_format_dt(last.get("started", "")))
            self.open_report_btn.setEnabled(bool(last.get("report_paths")))
        else:
            self._cards["vulns"].set_value("0")
            self._cards["vulns"].set_caption("no completed scans yet")
            self._cards["coverage"].set_value("—")
            self.risk_meter.reset()
            self._last_target_label.setText("No scans yet")
            self._last_time_label.setText("")
            self.open_report_btn.setEnabled(False)

        self._cards["version"].set_value(f"v{GUI_VERSION}")
        self._cards["version"].set_caption(f"Engine {ENGINE_VERSION}")

        targets = history.recent_targets(limit=8)
        self._recent_list.clear()
        for target in targets:
            item = QListWidgetItem(target)
            item.setToolTip("Double-click to start a new scan")
            self._recent_list.addItem(item)

    def _apply_card_icons(self, palette: Palette) -> None:
        icon_fns = {
            "scans": icons.icon_history,
            "vulns": icons.icon_alert,
            "coverage": icons.icon_doc,
            "version": icons.icon_about,
        }
        for key, fn in icon_fns.items():
            card = self._cards.get(key)
            if card is not None:
                card.set_icon(fn(20, palette.subtext))

    @staticmethod
    def _restyle(widget: QWidget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.risk_meter.apply_palette(palette)
        self._apply_card_icons(palette)
        for card in self._cards.values():
            card.apply_palette(palette)
        self.refresh()
