"""
Scan page — target, mode, threading/output options, progress, and live logs.
"""

import logging
import os
import time

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from gui.resources import icons
from gui.resources.styles import Palette
from gui.widgets.log_view import LogView

logger = logging.getLogger("SeaScanner.GUI.ScanPage")

MODES = {
    "quick": "Quick Scan",
    "standard": "Standard Scan",
    "deep": "Deep Scan",
}


def _normalize_target(raw: str) -> str:
    target = (raw or "").strip()
    if not target:
        raise ValueError("Target URL cannot be empty.")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


class ScanPage(QWidget):
    scan_requested = Signal()

    def __init__(self, controller, settings_store, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.settings_store = settings_store
        self._palette = None
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(500)
        self._elapsed_timer.timeout.connect(self._tick_elapsed)
        self._scan_start_wall = 0.0
        self._last_progress = 0

        title = QLabel("Scan")
        title.setProperty("title", True)
        subtitle = QLabel("Configure and launch a security assessment against a target")
        subtitle.setProperty("subtitle", True)

        # ---- Target ----
        target_box = QGroupBox("Target")
        target_layout = QVBoxLayout(target_box)
        target_layout.setSpacing(8)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com")
        self.target_input.setClearButtonEnabled(True)
        target_layout.addWidget(self.target_input)

        # ---- Scan options ----
        options_box = QGroupBox("Scan Options")
        options_layout = QGridLayout(options_box)
        options_layout.setHorizontalSpacing(14)
        options_layout.setVerticalSpacing(12)

        options_layout.addWidget(QLabel("Scan Mode"), 0, 0)
        self.mode_combo = QComboBox()
        for key, label in MODES.items():
            self.mode_combo.addItem(label, key)
        options_layout.addWidget(self.mode_combo, 0, 1)

        options_layout.addWidget(QLabel("Thread Count"), 0, 2)
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 32)
        options_layout.addWidget(self.thread_spin, 0, 3)

        options_layout.addWidget(QLabel("Timeout (seconds)"), 1, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 120)
        options_layout.addWidget(self.timeout_spin, 1, 1)

        options_layout.addWidget(QLabel("Output Options"), 2, 0)
        output_widget = QWidget()
        output_layout = QHBoxLayout(output_widget)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.setSpacing(16)
        self.html_check = QCheckBox("HTML Report")
        self.html_check.setChecked(True)
        self.pdf_check = QCheckBox("PDF Report")
        self.pdf_check.setToolTip("PDF generation requires WeasyPrint (future-ready)")
        output_layout.addWidget(self.html_check)
        output_layout.addWidget(self.pdf_check)
        options_layout.addWidget(output_widget, 2, 1, 1, 3)

        # ---- Actions ----
        actions_box = QGroupBox("Actions")
        actions_layout = QHBoxLayout(actions_box)
        actions_layout.setSpacing(10)
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.setIcon(icons.icon_play())
        self.start_btn.clicked.connect(self._on_start_clicked)
        self.cancel_btn = QPushButton("Cancel Scan")
        self.cancel_btn.setObjectName("dangerButton")
        self.cancel_btn.setIcon(icons.icon_stop())
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._on_cancel_clicked)
        self.open_report_btn = QPushButton("Open Report")
        self.open_report_btn.setIcon(icons.icon_doc())
        self.open_report_btn.setEnabled(False)
        self.open_report_btn.clicked.connect(self._on_open_report_clicked)
        self.open_folder_btn = QPushButton("Open Reports Folder")
        self.open_folder_btn.setIcon(icons.icon_folder())
        self.open_folder_btn.clicked.connect(self._on_open_folder_clicked)
        actions_layout.addWidget(self.start_btn)
        actions_layout.addWidget(self.cancel_btn)
        actions_layout.addStretch(1)
        actions_layout.addWidget(self.open_report_btn)
        actions_layout.addWidget(self.open_folder_btn)

        # ---- Progress ----
        progress_box = QGroupBox("Progress")
        progress_layout = QGridLayout(progress_box)
        progress_layout.setHorizontalSpacing(14)
        progress_layout.setVerticalSpacing(10)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar, 0, 0, 1, 4)

        progress_layout.addWidget(QLabel("Current Module"), 1, 0)
        self.module_label = QLabel("—")
        self.module_label.setProperty("muted", True)
        progress_layout.addWidget(self.module_label, 1, 1)

        progress_layout.addWidget(QLabel("Elapsed Time"), 1, 2)
        self.elapsed_label = QLabel("0.0s")
        self.elapsed_label.setProperty("muted", True)
        progress_layout.addWidget(self.elapsed_label, 1, 3)

        progress_layout.addWidget(QLabel("Estimated Remaining"), 2, 0)
        self.remaining_label = QLabel("—")
        self.remaining_label.setProperty("muted", True)
        progress_layout.addWidget(self.remaining_label, 2, 1)

        progress_layout.addWidget(QLabel("Live Status"), 2, 2)
        self.status_label = QLabel("Ready")
        self.status_label.setProperty("muted", True)
        progress_layout.addWidget(self.status_label, 2, 3)

        # ---- Live logs ----
        logs_box = QGroupBox("Live Logs")
        logs_layout = QVBoxLayout(logs_box)
        logs_layout.setSpacing(8)
        log_toolbar = QHBoxLayout()
        log_toolbar.addStretch(1)
        clear_btn = QPushButton("Clear")
        clear_btn.setIcon(icons.icon_clear())
        clear_btn.clicked.connect(self._on_clear_logs_clicked)
        save_btn = QPushButton("Save Logs")
        save_btn.setIcon(icons.icon_save())
        save_btn.clicked.connect(self._on_save_logs_clicked)
        log_toolbar.addWidget(clear_btn)
        log_toolbar.addWidget(save_btn)
        logs_layout.addLayout(log_toolbar)
        self.log_view = LogView()
        self.log_view.setMinimumHeight(220)
        logs_layout.addWidget(self.log_view)

        # ---- Compose ----
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(28, 24, 28, 24)
        content_layout.setSpacing(16)
        content_layout.addWidget(title)
        content_layout.addWidget(subtitle)
        content_layout.addWidget(target_box)
        content_layout.addWidget(options_box)
        content_layout.addWidget(actions_box)
        content_layout.addWidget(progress_box)
        content_layout.addWidget(logs_box, 1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(content)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)

        self._restore_from_settings()

    # ---------- settings ----------
    def _restore_from_settings(self) -> None:
        settings = self.settings_store
        mode = settings.sanitize_mode(settings.get("default_scan_mode"))
        self.set_mode(mode)
        self.thread_spin.setValue(int(settings.get("default_thread_count")))
        self.timeout_spin.setValue(int(settings.get("default_timeout")))
        self.html_check.setChecked(bool(settings.get("output_html")))
        self.pdf_check.setChecked(bool(settings.get("output_pdf")))
        if settings.get("remember_last_target") and settings.get("last_target"):
            self.target_input.setText(settings.get("last_target"))

    def set_mode(self, mode: str) -> None:
        mode = self.settings_store.sanitize_mode(mode)
        index = self.mode_combo.findData(mode)
        if index >= 0:
            self.mode_combo.setCurrentIndex(index)
        self.mode_combo.setToolTip(
            "Quick: fast, few pages. Standard: balanced. Deep: exhaustive + JS crawling.")

    def current_mode(self) -> str:
        return self.mode_combo.currentData() or "standard"

    # ---------- actions ----------
    def _on_start_clicked(self) -> None:
        if self.controller.running:
            return
        try:
            target = _normalize_target(self.target_input.text())
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid URL", str(exc))
            return

        mode = self.current_mode()
        thread_count = self.thread_spin.value()
        timeout = self.timeout_spin.value()
        outputs = {
            "html": self.html_check.isChecked(),
            "pdf": self.pdf_check.isChecked(),
        }
        report_dir = self.settings_store.get("default_report_dir") or ""

        if self.settings_store.get("remember_last_target"):
            self.settings_store.set("last_target", target)
            self.settings_store.save()

        ok = self.controller.start_scan(
            target=target,
            mode=mode,
            thread_count=thread_count,
            timeout=timeout,
            outputs=outputs,
            report_dir=report_dir,
        )
        if not ok:
            return
        self.scan_requested.emit()
        self._set_scanning_state(True)
        self._scan_start_wall = time.monotonic()
        self._last_progress = 0
        self.log_view.clear_logs()
        self.progress_bar.setValue(0)
        self.module_label.setText("Initializing...")
        self.status_label.setText("Scanning...")
        self._elapsed_timer.start()

    def _on_cancel_clicked(self) -> None:
        self.controller.cancel_scan()
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setText("Cancelling...")

    def _on_open_report_clicked(self) -> None:
        path = self._latest_report_path()
        if not path:
            QMessageBox.information(self, "No Report", "No report has been generated yet.")
            return
        self._open_path(path)

    def _on_open_folder_clicked(self) -> None:
        report_dir = self.settings_store.get("default_report_dir") or ""
        target_dir = report_dir or os.path.join(os.getcwd(), "reports")
        os.makedirs(target_dir, exist_ok=True)
        self._open_path(target_dir)

    def _on_clear_logs_clicked(self) -> None:
        self.log_view.clear_logs()

    def _on_save_logs_clicked(self) -> None:
        default_name = os.path.join(
            self.settings_store.get("default_report_dir") or "logs",
            f"scan_logs_{time.strftime('%Y%m%d_%H%M%S')}.txt",
        )
        path, _ = QFileDialog.getSaveFileName(self, "Save Logs", default_name, "Text Files (*.txt)")
        if path:
            if self.log_view.save_to_file(path):
                self.log_view.append_log("info", f"Logs saved to {path}")

    @staticmethod
    def _open_path(path: str) -> None:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _latest_report_path(self) -> str:
        summary = self.controller.last_summary
        if summary and summary.get("report_paths"):
            return summary["report_paths"][0]
        return ""

    # ---------- controller wiring ----------
    def on_progress(self, value: int, message: str) -> None:
        self._last_progress = value
        self.progress_bar.setValue(value)
        if message:
            self.status_label.setText(message)

    def on_stage(self, stage: str) -> None:
        self.status_label.setText(stage)
        self.module_label.setText(stage)

    def on_module_started(self, _name: str, label: str) -> None:
        self.module_label.setText(label)
        self.status_label.setText(label)

    def on_log(self, level: str, message: str) -> None:
        self.log_view.append_log(level, message)

    def on_scan_finished(self, summary: dict) -> None:
        self._stop_elapsed()
        self._set_scanning_state(False)
        self.progress_bar.setValue(100)
        self.module_label.setText("Completed")
        self.status_label.setText("Scan completed")
        self.open_report_btn.setEnabled(bool(summary.get("report_paths")))
        if summary.get("report_paths"):
            self.log_view.append_log("info", f"Report ready: {summary['report_paths'][0]}")

    def on_scan_failed(self, message: str) -> None:
        self._stop_elapsed()
        self._set_scanning_state(False)
        self.module_label.setText("Failed")
        self.status_label.setText("Scan failed")
        self.log_view.append_log("error", f"Scan failed: {message}")

    def on_scan_cancelled(self) -> None:
        self._stop_elapsed()
        self._set_scanning_state(False)
        self.module_label.setText("Cancelled")
        self.status_label.setText("Scan cancelled")
        self.log_view.append_log("warning", "Scan was cancelled by the user")

    def on_scan_started(self) -> None:
        self.cancel_btn.setText("Cancel Scan")

    # ---------- internal state ----------
    def _set_scanning_state(self, scanning: bool) -> None:
        self.start_btn.setEnabled(not scanning)
        self.cancel_btn.setEnabled(scanning)
        self.cancel_btn.setText("Cancel Scan")
        for widget in (self.target_input, self.mode_combo, self.thread_spin,
                       self.timeout_spin, self.html_check, self.pdf_check):
            widget.setEnabled(not scanning)

    def _stop_elapsed(self) -> None:
        self._elapsed_timer.stop()
        elapsed = time.monotonic() - self._scan_start_wall if self._scan_start_wall else 0.0
        self.elapsed_label.setText(f"{elapsed:.1f}s")
        self.remaining_label.setText("—")

    def _tick_elapsed(self) -> None:
        elapsed = time.monotonic() - self._scan_start_wall
        self.elapsed_label.setText(f"{elapsed:.1f}s")
        progress = self._last_progress
        if progress > 0:
            remaining = elapsed / progress * (100 - progress)
            self.remaining_label.setText(f"{remaining:.0f}s")

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.log_view.apply_palette(palette)
