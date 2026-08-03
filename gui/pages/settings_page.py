"""
Settings page — theme, scan defaults, and output behavior, persisted to JSON
via SettingsStore. Uses the new segmented control and toggle switch widgets.
"""

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from gui.resources.styles import Palette
from gui.widgets.cards import PanelCard, SectionCard
from gui.widgets.controls import SegmentedControl, ToggleSwitch

logger = logging.getLogger("SeaScanner.GUI.SettingsPage")

THEMES = [("system", "System"), ("dark", "Dark"), ("light", "Light")]


def _row(title: str, subtitle: str, widget: QWidget, hint: str = "") -> QWidget:
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(16)

    col = QVBoxLayout()
    col.setSpacing(1)
    label = QLabel(title)
    label.setObjectName("cardTitle")
    col.addWidget(label)
    if subtitle:
        sub = QLabel(subtitle)
        sub.setProperty("muted", True)
        sub.setProperty("small", True)
        sub.setWordWrap(True)
        col.addWidget(sub)
    if hint:
        h = QLabel(hint)
        h.setProperty("muted", True)
        h.setProperty("small", True)
        col.addWidget(h)
    layout.addLayout(col, 1)

    layout.addWidget(widget, 0, Qt.AlignmentFlag.AlignRight)
    row.setLayout(layout)
    return row


class SettingsPage(QWidget):
    settings_saved = Signal()

    def __init__(self, settings_store, parent=None):
        super().__init__(parent)
        self.settings_store = settings_store
        self._palette = None

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(32, 28, 32, 28)
        body_layout.setSpacing(18)

        body_layout.addWidget(SectionCard(
            "Settings",
            "Preferences",
            "Stored as JSON in the user data directory and applied immediately.",
        ))

        appearance = PanelCard("Appearance")
        self.theme_segment = SegmentedControl()
        for key, label in THEMES:
            self.theme_segment.add_option(label, key)
        appearance.body().addWidget(_row(
            "Theme",
            "Colour scheme used across the interface.",
            self.theme_segment,
        ))
        body_layout.addWidget(appearance)

        defaults = PanelCard("Scan Defaults")
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 32)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 120)
        defaults.body().addWidget(_row(
            "Default Scan Mode",
            "Preselected profile on the Scanner page.",
            self._build_mode_widget(),
        ))
        defaults.body().addWidget(_row(
            "Default Thread Count",
            "Parallel workers used for page-level scanners.",
            self.thread_spin,
        ))
        defaults.body().addWidget(_row(
            "Default Timeout (s)",
            "Per-request timeout for HTTP interactions.",
            self.timeout_spin,
        ))

        dir_row = QWidget()
        dir_layout = QHBoxLayout(dir_row)
        dir_layout.setContentsMargins(0, 0, 0, 0)
        dir_layout.setSpacing(8)
        self.report_dir_input = QLineEdit()
        self.report_dir_input.setPlaceholderText("reports")
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._on_browse_dir_clicked)
        dir_layout.addWidget(self.report_dir_input, 1)
        dir_layout.addWidget(browse_btn)
        defaults.body().addWidget(_row(
            "Default Report Directory",
            "Where generated HTML / PDF reports are written.",
            dir_row,
        ))
        body_layout.addWidget(defaults)

        behavior = PanelCard("Behavior")
        self.auto_open_switch = ToggleSwitch()
        self.remember_switch = ToggleSwitch()
        self.html_switch = ToggleSwitch()
        self.pdf_switch = ToggleSwitch()
        self._toggles = (self.auto_open_switch, self.remember_switch,
                         self.html_switch, self.pdf_switch)
        behavior.body().addWidget(_row(
            "Auto-open report",
            "Open the HTML report when a scan finishes.",
            self.auto_open_switch,
        ))
        behavior.body().addWidget(_row(
            "Remember last target",
            "Pre-fill the target field from the previous scan.",
            self.remember_switch,
        ))
        behavior.body().addWidget(_row(
            "HTML report by default",
            "Enable HTML output for new scans.",
            self.html_switch,
        ))
        behavior.body().addWidget(_row(
            "PDF report by default",
            "Enable PDF output (requires WeasyPrint, future-ready).",
            self.pdf_switch,
        ))
        body_layout.addWidget(behavior)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.setObjectName("ghostButton")
        reset_btn.clicked.connect(self._on_reset_clicked)
        save_btn = QPushButton("Save Settings")
        save_btn.setObjectName("primaryButton")
        save_btn.clicked.connect(self._on_save_clicked)
        actions.addWidget(reset_btn)
        actions.addStretch(1)
        actions.addWidget(save_btn)
        body_layout.addLayout(actions)
        body_layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(body)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(scroll)

        self._load_into_widgets()

    def _build_mode_widget(self) -> QWidget:
        self.mode_segment = SegmentedControl()
        for key, label in (("quick", "Quick"), ("standard", "Standard"), ("deep", "Deep")):
            self.mode_segment.add_option(label, key)
        return self.mode_segment

    # ---------------------------------------------------------- load / save
    def _load_into_widgets(self) -> None:
        s = self.settings_store
        self.theme_segment.set_current(s.get("theme"))
        self.mode_segment.set_current(s.sanitize_mode(s.get("default_scan_mode")))
        self.thread_spin.setValue(int(s.get("default_thread_count")))
        self.timeout_spin.setValue(int(s.get("default_timeout")))
        self.report_dir_input.setText(s.get("default_report_dir") or "")
        self.auto_open_switch.setChecked(bool(s.get("auto_open_report")))
        self.remember_switch.setChecked(bool(s.get("remember_last_target")))
        self.html_switch.setChecked(bool(s.get("output_html")))
        self.pdf_switch.setChecked(bool(s.get("output_pdf")))

    def _collect_values(self) -> dict:
        return {
            "theme": self.theme_segment.current_value() or "dark",
            "default_scan_mode": self.mode_segment.current_value() or "standard",
            "default_thread_count": self.thread_spin.value(),
            "default_timeout": self.timeout_spin.value(),
            "default_report_dir": self.report_dir_input.text().strip(),
            "auto_open_report": self.auto_open_switch.isChecked(),
            "remember_last_target": self.remember_switch.isChecked(),
            "output_html": self.html_switch.isChecked(),
            "output_pdf": self.pdf_switch.isChecked(),
        }

    # --------------------------------------------------------------- slots
    def _on_save_clicked(self) -> None:
        values = self._collect_values()
        if not values["output_html"] and not values["output_pdf"]:
            QMessageBox.warning(
                self, "Output Options",
                "At least one report format should remain enabled.")
            return
        self.settings_store.update(values)
        self.settings_store.save()
        self.settings_saved.emit()

    def _on_reset_clicked(self) -> None:
        from gui.services.settings_store import DEFAULTS
        for key, value in DEFAULTS.items():
            self.settings_store.set(key, value)
        self.settings_store.save()
        self._load_into_widgets()
        self.settings_saved.emit()
        QMessageBox.information(self, "Settings", "Settings reset to defaults.")

    def _on_browse_dir_clicked(self) -> None:
        start = self.report_dir_input.text().strip() or "reports"
        chosen = QFileDialog.getExistingDirectory(self, "Choose Report Directory", start)
        if chosen:
            self.report_dir_input.setText(chosen)

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        for toggle in self._toggles:
            toggle.apply_palette(palette)
