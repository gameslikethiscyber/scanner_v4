"""
SummaryView — consolidated scan results panel reused by the scanner workspace
and the history detail pane. Shows risk readout, KPI strip, findings table and
report actions. No fabricated data; rendered strictly from the summary dict.
"""

import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui.resources import icons
from gui.resources.styles import DARK, Palette, severity_color, status_color
from gui.widgets.cards import KpiCard
from gui.widgets.risk_meter import RiskMeter


class SummaryView(QWidget):
    open_report = Signal()
    open_folder = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._palette = DARK
        self._summary = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        top = QHBoxLayout()
        top.setSpacing(16)
        self.risk_meter = RiskMeter()
        top.addWidget(self.risk_meter, 3)

        self._kpi_cards = {}
        kpi_widget = QWidget()
        kpi_grid = QVBoxLayout(kpi_widget)
        kpi_grid.setContentsMargins(0, 0, 0, 0)
        kpi_grid.setSpacing(10)
        for key, title, icon in (
            ("severity", "Overall Severity", icons.icon_scanner()),
            ("confidence", "Confidence", icons.icon_about()),
            ("duration", "Duration", icons.icon_history()),
            ("coverage", "Coverage", icons.icon_doc()),
        ):
            card = KpiCard(title, icon=icon)
            kpi_grid.addWidget(card)
            self._kpi_cards[key] = card
        top.addWidget(kpi_widget, 2)
        layout.addLayout(top)

        self._meta_label = QLabel("No scan results yet.")
        self._meta_label.setProperty("subtitle", True)
        layout.addWidget(self._meta_label)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.open_report_btn = QPushButton("Open Report")
        self.open_report_btn.setIcon(icons.icon_doc())
        self.open_report_btn.clicked.connect(self.open_report)
        self.open_folder_btn = QPushButton("Open Reports Folder")
        self.open_folder_btn.setIcon(icons.icon_folder())
        self.open_folder_btn.clicked.connect(self.open_folder)
        actions.addWidget(self.open_report_btn)
        actions.addWidget(self.open_folder_btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        self._count_label = QLabel("")
        self._count_label.setProperty("muted", True)
        self._count_label.setProperty("small", True)
        layout.addWidget(self._count_label)

        self.findings_table = QTableWidget(0, 5)
        self.findings_table.setHorizontalHeaderLabels(
            ["Severity", "Status", "Module", "Finding", "Target"])
        self.findings_table.verticalHeader().setVisible(False)
        self.findings_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.findings_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.findings_table.setAlternatingRowColors(True)
        self.findings_table.setMinimumHeight(240)
        header = self.findings_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.findings_table, 1)

        self._empty = QLabel("Run a scan to see the findings summary here.")
        self._empty.setProperty("muted", True)
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._empty)

    # ------------------------------------------------------------------ data
    def display_summary(self, summary: dict) -> None:
        self._summary = summary
        palette = self._palette
        stats = summary.get("stats") or {}

        tier = summary.get("overall_tier", "none")
        score = summary.get("risk_score", 0)
        self.risk_meter.set_risk(score, tier, summary.get("overall_description", ""))

        self._kpi_cards["severity"].set_value(summary.get("overall_severity", "No Risk"))
        self._kpi_cards["severity"].set_accent(summary.get("overall_color", "#38bdf8"))

        confidence = summary.get("confidence")
        self._kpi_cards["confidence"].set_value(
            f"{confidence}%" if confidence is not None else "—")
        if "modules_completed" in summary:
            self._kpi_cards["confidence"].set_caption(
                f"{summary.get('modules_completed', 0)} modules completed")

        duration = summary.get("duration")
        self._kpi_cards["duration"].set_value(
            f"{duration:.1f}s" if duration is not None else "—")

        coverage = summary.get("coverage")
        self._kpi_cards["coverage"].set_value(
            f"{coverage}%" if coverage is not None else "—")
        caption_parts = []
        if "vulnerabilities" in summary:
            caption_parts.append(f"{summary.get('vulnerabilities', 0)} vulnerabilities")
        if "requests_sent" in summary:
            caption_parts.append(f"{summary.get('requests_sent', 0)} requests")
        if "pages_crawled" in summary:
            caption_parts.append(f"{summary.get('pages_crawled', 0)} pages")
        self._kpi_cards["coverage"].set_caption(" · ".join(caption_parts))

        meta_parts = []
        if summary.get("target"):
            meta_parts.append(f"Target: {summary.get('target', '')}")
        if summary.get("mode"):
            meta_parts.append(summary.get("mode", ""))
        auth_mode = summary.get("auth_mode")
        if auth_mode and auth_mode.lower() != "anonymous":
            session_valid = summary.get("auth_session_valid")
            meta_parts.append(
                f"Auth: {auth_mode}"
                + (" (session valid)" if session_valid else " (session invalid)")
            )
        if "started" in summary:
            meta_parts.append(str(summary.get("started", "")).replace("T", " ")[:16])
        self._meta_label.setText("   ·   ".join(meta_parts))

        findings = summary.get("findings", [])
        self._populate_findings(findings)
        self._count_label.setText(f"{len(findings)} finding(s) recorded")
        has_reports = bool(summary.get("report_paths"))
        self.open_report_btn.setEnabled(has_reports)
        self._empty.setVisible(not findings)

    def clear_results(self) -> None:
        self._summary = None
        self.risk_meter.reset()
        for card in self._kpi_cards.values():
            card.set_value("—")
            card.set_caption("")
            card.set_accent(None)
        self._meta_label.setText("No scan results yet.")
        self.findings_table.setRowCount(0)
        self._count_label.setText("")
        self.open_report_btn.setEnabled(False)
        self._empty.setText("Run a scan to see the findings summary here.")
        self._empty.setVisible(True)

    # -------------------------------------------------------------- findings
    def _populate_findings(self, findings: list) -> None:
        palette = self._palette
        self.findings_table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            severity = finding.get("severity", "")
            status = finding.get("status", "")
            module = finding.get("module", "")
            confidence = finding.get("confidence", 0)
            title = finding.get("title") or finding.get("reason") or module
            target = finding.get("target", "")

            items = [
                (severity.capitalize() or "—", severity_color(severity, palette), QFont.Weight.Bold),
                (status.capitalize() or "—", status_color(status, palette), None),
                (module or "—", None, None),
                (f"{confidence}%", None, None),
                (title or "—", None, None),
            ]
            for col, (text, color, weight) in enumerate(items):
                item = QTableWidgetItem(text)
                if color:
                    item.setForeground(QColor(color))
                if weight:
                    font = item.font()
                    font.setWeight(weight)
                    item.setFont(font)
                self.findings_table.setItem(row, col, item)

    def _status_text(self, status: str) -> str:
        return (status or "—").capitalize()

    # ----------------------------------------------------------------- theme
    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        for card in self._kpi_cards.values():
            card.apply_palette(palette)
        if self._summary:
            self.display_summary(self._summary)
