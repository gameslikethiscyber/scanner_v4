"""
Scanner workspace — a single page with three states: setup → running →
completed. Replaces the previous separate Scan + Results pages and removes the
repetition of a duplicated summary view.
"""

import logging
import os
import time

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from gui.resources import icons
from gui.resources.styles import DARK, Palette
from gui.widgets.cards import SectionCard
from gui.widgets.controls import SegmentedControl
from gui.widgets.log_view import LogView
from gui.widgets.summary import SummaryView

logger = logging.getLogger("SeaScanner.GUI.ScanPage")

MODES = {
    "quick": "Quick",
    "standard": "Standard",
    "deep": "Deep",
}
MODE_HINTS = {
    "quick": "Fast check — few pages, minimal load",
    "standard": "Balanced depth and coverage",
    "deep": "Exhaustive — more pages, JS crawling",
}


def _normalize_target(raw: str) -> str:
    target = (raw or "").strip()
    if not target:
        raise ValueError("Target URL cannot be empty.")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


class ScannerPage(QWidget):
    scan_requested = Signal()

    STATE_SETUP = 0
    STATE_RUNNING = 1
    STATE_COMPLETED = 2

    def __init__(self, controller, settings_store, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.settings_store = settings_store
        self._palette = DARK
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(500)
        self._elapsed_timer.timeout.connect(self._tick_elapsed)
        self._scan_start_wall = 0.0
        self._last_progress = 0
        self._summary = None

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(32, 28, 32, 28)
        body_layout.setSpacing(18)

        self._header = SectionCard(
            "Scanner", "Security Assessment",
            "Configure and run a scan, then review the consolidated results.")
        body_layout.addWidget(self._header)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_setup())
        self.stack.addWidget(self._build_running())
        self.stack.addWidget(self._build_completed())
        body_layout.addWidget(self.stack, 1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(body)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(scroll)

        self._restore_from_settings()
        self._set_state(self.STATE_SETUP)

    # -------------------------------------------------------------- builders
    def _build_setup(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)

        # Target
        target_frame = QWidget()
        target_frame.setObjectName("card")
        target_layout = QVBoxLayout(target_frame)
        target_layout.setContentsMargins(18, 16, 18, 16)
        target_layout.setSpacing(8)
        target_title = QLabel("TARGET")
        target_title.setProperty("kicker", True)
        target_layout.addWidget(target_title)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com")
        self.target_input.setClearButtonEnabled(True)
        self.target_input.returnPressed.connect(self._on_start_clicked)
        target_layout.addWidget(self.target_input)
        hint = QLabel("Hostname or full URL. Scheme defaults to HTTPS.")
        hint.setProperty("muted", True)
        hint.setProperty("small", True)
        target_layout.addWidget(hint)
        layout.addWidget(target_frame)

        # Options
        options_frame = QWidget()
        options_frame.setObjectName("card")
        options_layout = QVBoxLayout(options_frame)
        options_layout.setContentsMargins(18, 16, 18, 16)
        options_layout.setSpacing(12)
        options_title = QLabel("SCAN PROFILE")
        options_title.setProperty("kicker", True)
        options_layout.addWidget(options_title)

        self.mode_segment = SegmentedControl()
        for key in ("quick", "standard", "deep"):
            self.mode_segment.add_option(MODES[key], key, MODE_HINTS[key])
        options_layout.addWidget(self.mode_segment, 0, Qt.AlignmentFlag.AlignLeft)
        self.mode_hint_label = QLabel(MODE_HINTS["standard"])
        self.mode_hint_label.setProperty("muted", True)
        self.mode_hint_label.setProperty("small", True)
        options_layout.addWidget(self.mode_hint_label)

        row = QHBoxLayout()
        row.setSpacing(24)
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 32)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 120)
        row.addWidget(self._spin_block("Threads", self.thread_spin))
        row.addWidget(self._spin_block("Timeout (s)", self.timeout_spin))
        row.addStretch(1)
        options_layout.addLayout(row)

        self.html_check = QCheckBox("HTML report")
        self.html_check.setChecked(True)
        self.pdf_check = QCheckBox("PDF report")
        self.pdf_check.setToolTip("PDF generation requires WeasyPrint (future-ready)")
        out_row = QHBoxLayout()
        out_row.setSpacing(20)
        out_row.addWidget(self.html_check)
        out_row.addWidget(self.pdf_check)
        out_row.addStretch(1)
        options_layout.addLayout(out_row)
        layout.addWidget(options_frame)

        layout.addWidget(self._build_auth_section())
        layout.addWidget(self._build_crawl_settings())

        self.start_btn = QPushButton("Start Scan")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.setIcon(icons.icon_play())
        self.start_btn.setMinimumHeight(44)
        self.start_btn.clicked.connect(self._on_start_clicked)
        layout.addWidget(self.start_btn)

        layout.addStretch(1)
        return page

    def _build_auth_section(self) -> QWidget:
        """Optional Authentication card (SOP v4.0 Phase 1). Hidden state default."""
        frame = QWidget()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        title = QLabel("AUTHENTICATION (OPTIONAL)")
        title.setProperty("kicker", True)
        layout.addWidget(title)

        self.auth_enable_check = QCheckBox("Enable authenticated scanning")
        self.auth_enable_check.setToolTip(
            "Attach cookies, a token or custom headers to the scan session. "
            "Anonymous scanning remains the default.")
        self.auth_enable_check.toggled.connect(self._on_auth_enable_toggled)
        layout.addWidget(self.auth_enable_check)

        self.auth_fields = QWidget()
        fields = QVBoxLayout(self.auth_fields)
        fields.setContentsMargins(0, 0, 0, 0)
        fields.setSpacing(10)

        type_row = QHBoxLayout()
        type_row.setSpacing(8)
        self.auth_type_group = QButtonGroup(self)
        self._auth_keys = ("cookies", "bearer", "jwt", "headers")
        self._auth_radios = {}
        for index, key in enumerate(self._auth_keys):
            label = {
                "cookies": "Cookies", "bearer": "Bearer",
                "jwt": "JWT", "headers": "Custom Headers",
            }[key]
            radio = QRadioButton(label)
            self.auth_type_group.addButton(radio, index)
            type_row.addWidget(radio)
            self._auth_radios[key] = radio
        self._auth_radios["cookies"].setChecked(True)
        self.auth_type_group.idClicked.connect(self._on_auth_type_changed)
        type_row.addStretch(1)
        fields.addLayout(type_row)

        self.auth_stack = QStackedWidget()
        self.auth_stack.addWidget(self._build_cookie_fields())
        self.auth_stack.addWidget(self._build_token_fields())
        self.auth_stack.addWidget(self._build_token_fields())
        self.auth_stack.addWidget(self._build_header_fields())
        self.auth_stack.setCurrentIndex(0)
        fields.addWidget(self.auth_stack)

        self.auth_validate_check = QCheckBox("Validate session before scanning")
        self.auth_validate_check.setChecked(True)
        self.auth_validate_check.setToolTip(
            "Probe the target with the configured credentials before scanning. "
            "On failure the scan continues anonymously.")
        fields.addWidget(self.auth_validate_check)

        auth_hint = QLabel(
            "Login page detected? Enable authentication and re-run to reach protected areas.")
        auth_hint.setProperty("muted", True)
        auth_hint.setProperty("small", True)
        auth_hint.setWordWrap(True)
        fields.addWidget(auth_hint)

        layout.addWidget(self.auth_fields)
        self.auth_fields.setVisible(False)
        return frame

    def _build_crawl_settings(self) -> QWidget:
        """Crawl Settings card (SOP v4.0 Phase 2)."""
        frame = QWidget()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        title = QLabel("CRAWL SETTINGS")
        title.setProperty("kicker", True)
        layout.addWidget(title)

        hint = QLabel("Controls scope, depth and discovery sources. Anonymous default unchanged.")
        hint.setProperty("muted", True)
        hint.setProperty("small", True)
        layout.addWidget(hint)

        row1 = QHBoxLayout()
        row1.setSpacing(20)

        self.crawl_max_depth_spin = QSpinBox()
        self.crawl_max_depth_spin.setRange(0, 60)
        self.crawl_max_depth_spin.setValue(10)
        self.crawl_max_depth_spin.setSpecialValueText("Unlimited")
        row1.addWidget(self._spin_block("Max Depth", self.crawl_max_depth_spin))

        self.crawl_duration_spin = QSpinBox()
        self.crawl_duration_spin.setRange(0, 3600)
        self.crawl_duration_spin.setSuffix(" s")
        self.crawl_duration_spin.setValue(0)
        self.crawl_duration_spin.setSpecialValueText("Unlimited")
        row1.addWidget(self._spin_block("Max Duration", self.crawl_duration_spin))

        self.crawl_scope_combo = QComboBox()
        for key, label in (("domain", "Entire domain (subdomains)"),
                           ("subdomain", "Current subdomain"),
                           ("path", "Current path only"),
                           ("all", "All hosts")):
            self.crawl_scope_combo.addItem(label, key)
        row1.addWidget(self._spin_block("Scope", self.crawl_scope_combo))
        row1.addStretch(1)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(20)
        self.crawl_subdomains_check = QCheckBox("Include subdomains")
        self.crawl_robots_check = QCheckBox("Respect robots.txt")
        self.crawl_sitemap_check = QCheckBox("Parse sitemap.xml")
        self.crawl_sitemap_check.setChecked(True)
        row2.addWidget(self.crawl_subdomains_check)
        row2.addWidget(self.crawl_robots_check)
        row2.addWidget(self.crawl_sitemap_check)
        row2.addStretch(1)
        layout.addLayout(row2)

        return frame

    def build_crawl_config(self) -> dict:
        """Return the Phase 2 crawl settings from the GUI state."""
        return {
            "depth": self.crawl_max_depth_spin.value(),
            "duration": self.crawl_duration_spin.value(),
            "scope": self.crawl_scope_combo.currentData()
                     or self.crawl_scope_combo.currentText(),
            "include_subdomains": self.crawl_subdomains_check.isChecked(),
            "respect_robots": self.crawl_robots_check.isChecked(),
            "parse_sitemap": self.crawl_sitemap_check.isChecked(),
        }

    def _build_cookie_fields(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        file_row = QHBoxLayout()
        self.auth_cookie_file = QLineEdit()
        self.auth_cookie_file.setPlaceholderText("Cookies file (Netscape or name=value)")
        self.auth_cookie_file.setClearButtonEnabled(True)
        file_row.addWidget(self.auth_cookie_file, 1)
        browse = QPushButton("Browse...")
        browse.clicked.connect(lambda: self._pick_file(self.auth_cookie_file))
        file_row.addWidget(browse)
        lay.addLayout(file_row)

        self.auth_cookie_string = QLineEdit()
        self.auth_cookie_string.setPlaceholderText("Or paste cookie string (name=value; name2=value2)")
        self.auth_cookie_string.setClearButtonEnabled(True)
        lay.addWidget(self.auth_cookie_string)
        return page

    def _build_token_fields(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        file_row = QHBoxLayout()
        self.auth_token_file = QLineEdit()
        self.auth_token_file.setPlaceholderText("Token file (first non-comment line)")
        self.auth_token_file.setClearButtonEnabled(True)
        file_row.addWidget(self.auth_token_file, 1)
        browse = QPushButton("Browse...")
        browse.clicked.connect(lambda: self._pick_file(self.auth_token_file))
        file_row.addWidget(browse)
        lay.addLayout(file_row)

        self.auth_token_value = QLineEdit()
        self.auth_token_value.setPlaceholderText("Or paste the token value")
        self.auth_token_value.setClearButtonEnabled(True)
        lay.addWidget(self.auth_token_value)
        return page

    def _build_header_fields(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        self.auth_headers_text = QPlainTextEdit()
        self.auth_headers_text.setPlaceholderText(
            "One header per line, e.g.:\nAuthorization: ApiKey 1234-abcd\nX-Api-Key: secret")
        self.auth_headers_text.setMaximumHeight(96)
        lay.addWidget(self.auth_headers_text)
        return page

    def _pick_file(self, target: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select Credentials File")
        if path:
            target.setText(path)

    # ---------------------------------------------------------- auth helpers
    def _on_auth_enable_toggled(self, checked: bool) -> None:
        self.auth_fields.setVisible(checked)

    def _on_auth_type_changed(self, _index: int) -> None:
        self.auth_stack.setCurrentIndex(max(0, int(_index)))

    def build_auth_spec(self):
        """Return an AuthSpec from the GUI state, or None for anonymous scans."""
        if not self.auth_enable_check.isChecked():
            return None
        from core.auth.base import AuthSpec
        auth_index = self.auth_type_group.checkedId()
        if auth_index < 0 or auth_index >= len(self._auth_keys):
            return None
        auth_type = self._auth_keys[auth_index]
        validate = self.auth_validate_check.isChecked()
        if auth_type == "cookies":
            return AuthSpec(type="cookies", cookie_file=self.auth_cookie_file.text().strip(),
                            cookie_string=self.auth_cookie_string.text().strip(),
                            validate=validate)
        if auth_type in ("bearer", "jwt"):
            return AuthSpec(type=auth_type, token_file=self.auth_token_file.text().strip(),
                            token=self.auth_token_value.text().strip(), validate=validate)
        if auth_type == "headers":
            headers = [
                ln.strip() for ln in self.auth_headers_text.toPlainText().splitlines()
                if ln.strip() and ":" in ln
            ]
            return AuthSpec(type="headers", headers=headers, validate=validate)
        return None

    @staticmethod
    def _spin_block(label_text: str, spin: QSpinBox) -> QWidget:
        box = QVBoxLayout()
        box.setSpacing(6)
        label = QLabel(label_text.upper())
        label.setProperty("kicker", True)
        box.addWidget(label)
        spin.setFixedWidth(120)
        box.addWidget(spin)
        holder = QWidget()
        holder.setLayout(box)
        return holder

    def _build_running(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        card = QWidget()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 16, 18, 16)
        card_layout.setSpacing(12)

        top = QHBoxLayout()
        self.state_pill = QLabel("SCANNING")
        self.state_pill.setObjectName("pill")
        self.state_pill.setProperty("state", "info")
        top.addWidget(self.state_pill)
        top.addStretch(1)
        self.elapsed_label = QLabel("0.0s")
        self.elapsed_label.setProperty("muted", True)
        top.addWidget(self.elapsed_label)
        card_layout.addLayout(top)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(10)
        card_layout.addWidget(self.progress_bar)

        self.stage_label = QLabel("Initializing...")
        self.stage_label.setObjectName("cardSub")
        self.stage_label.setWordWrap(True)
        card_layout.addWidget(self.stage_label)

        self.remaining_label = QLabel("Estimating remaining time...")
        self.remaining_label.setProperty("muted", True)
        self.remaining_label.setProperty("small", True)
        card_layout.addWidget(self.remaining_label)

        controls = QHBoxLayout()
        controls.setSpacing(10)
        self.cancel_btn = QPushButton("Cancel Scan")
        self.cancel_btn.setObjectName("dangerButton")
        self.cancel_btn.setIcon(icons.icon_cancel())
        self.cancel_btn.clicked.connect(self._on_cancel_clicked)
        controls.addWidget(self.cancel_btn)
        controls.addStretch(1)
        card_layout.addLayout(controls)
        layout.addWidget(card)

        self._running_logs = LogView()
        self._running_logs.setMinimumHeight(220)
        layout.addWidget(self._running_logs, 1)
        return page

    def _build_completed(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        top = QHBoxLayout()
        self.completed_pill = QLabel("COMPLETED")
        self.completed_pill.setObjectName("pill")
        self.completed_pill.setProperty("state", "success")
        top.addWidget(self.completed_pill)
        top.addStretch(1)
        self.completed_meta = QLabel("")
        self.completed_meta.setProperty("muted", True)
        self.completed_meta.setProperty("small", True)
        top.addWidget(self.completed_meta)
        layout.addLayout(top)

        self.summary_view = SummaryView()
        layout.addWidget(self.summary_view, 3)

        self._completed_logs = LogView()
        self._completed_logs.setMaximumHeight(180)
        self._completed_logs.setMinimumHeight(140)
        layout.addWidget(self._completed_logs, 1)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        save_logs_btn = QPushButton("Save Logs")
        save_logs_btn.setIcon(icons.icon_save())
        save_logs_btn.clicked.connect(self._on_save_logs_clicked)
        self.run_again_btn = QPushButton("Run New Scan")
        self.run_again_btn.setObjectName("primaryButton")
        self.run_again_btn.setIcon(icons.icon_refresh())
        self.run_again_btn.clicked.connect(self._reset_to_setup)
        actions.addWidget(save_logs_btn)
        actions.addStretch(1)
        actions.addWidget(self.run_again_btn)
        layout.addLayout(actions)
        return page

    # ------------------------------------------------------------ settings
    def _restore_from_settings(self) -> None:
        settings = self.settings_store
        self.set_mode(settings.sanitize_mode(settings.get("default_scan_mode")))
        self.thread_spin.setValue(int(settings.get("default_thread_count")))
        self.timeout_spin.setValue(int(settings.get("default_timeout")))
        self.html_check.setChecked(bool(settings.get("output_html")))
        self.pdf_check.setChecked(bool(settings.get("output_pdf")))
        if settings.get("remember_last_target") and settings.get("last_target"):
            self.target_input.setText(settings.get("last_target"))

    def set_mode(self, mode: str) -> None:
        mode = self.settings_store.sanitize_mode(mode)
        self.mode_segment.set_current(mode)
        self.mode_hint_label.setText(MODE_HINTS.get(mode, ""))

    def current_mode(self) -> str:
        return self.mode_segment.current_value() or "standard"

    def _active_log_view(self) -> LogView:
        if self.stack.currentIndex() == self.STATE_COMPLETED:
            return self._completed_logs
        return self._running_logs

    # ------------------------------------------------------------- actions
    def _on_start_clicked(self) -> None:
        if self.controller.running:
            return
        try:
            target = _normalize_target(self.target_input.text())
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Target", str(exc))
            return

        mode = self.current_mode()
        outputs = {
            "html": self.html_check.isChecked(),
            "pdf": self.pdf_check.isChecked(),
        }
        report_dir = self.settings_store.get("default_report_dir") or ""
        auth_spec = self.build_auth_spec()

        if self.settings_store.get("remember_last_target"):
            self.settings_store.set("last_target", target)
            self.settings_store.save()

        ok = self.controller.start_scan(
            target=target,
            mode=mode,
            thread_count=self.thread_spin.value(),
            timeout=self.timeout_spin.value(),
            outputs=outputs,
            report_dir=report_dir,
            auth_spec=auth_spec,
            crawl=self.build_crawl_config(),
        )
        if not ok:
            return
        self.scan_requested.emit()
        self._begin_running()

    def _begin_running(self) -> None:
        self._running_logs.clear_logs()
        self.progress_bar.setValue(0)
        self.stage_label.setText("Initializing...")
        self.remaining_label.setText("Estimating remaining time...")
        self.elapsed_label.setText("0.0s")
        self._scan_start_wall = time.monotonic()
        self._last_progress = 0
        self._elapsed_timer.start()
        self._set_state(self.STATE_RUNNING)

    def _on_cancel_clicked(self) -> None:
        self.controller.cancel_scan()
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setText("Cancelling...")

    def _on_save_logs_clicked(self) -> None:
        default_name = os.path.join(
            self.settings_store.get("default_report_dir") or "logs",
            f"scan_logs_{time.strftime('%Y%m%d_%H%M%S')}.txt",
        )
        path, _ = QFileDialog.getSaveFileName(self, "Save Logs", default_name, "Text Files (*.txt)")
        if path:
            if self._active_log_view().save_to_file(path):
                self._active_log_view().append_log("info", f"Logs saved to {path}")

    def _reset_to_setup(self) -> None:
        self._set_state(self.STATE_SETUP)

    # ------------------------------------------------------------- state
    def _set_state(self, state: int) -> None:
        self.stack.setCurrentIndex(state)

    # ------------------------------------------------------- controller api
    def on_scan_started(self) -> None:
        self.cancel_btn.setEnabled(True)
        self.cancel_btn.setText("Cancel Scan")

    def on_progress(self, value: int, message: str) -> None:
        self._last_progress = value
        self.progress_bar.setValue(value)
        if message:
            self.stage_label.setText(message)

    def on_stage(self, stage: str) -> None:
        self.stage_label.setText(stage)

    def on_module_started(self, _name: str, label: str) -> None:
        self.stage_label.setText(label)

    def on_module_finished(self, _name: str, _status: str, _detail: str) -> None:
        pass

    def on_log(self, level: str, message: str) -> None:
        self._active_log_view().append_log(level, message)

    def on_scan_finished(self, summary: dict) -> None:
        self._stop_elapsed()
        self.progress_bar.setValue(100)
        self.stage_label.setText("Scan completed")
        self._summary = summary
        self._completed_logs.clear_logs()
        self._completed_logs.append_log("info", f"Scan completed: {summary.get('target', '')}")
        for path in summary.get("report_paths", []):
            self._completed_logs.append_log("info", f"Report ready: {path}")
        self.summary_view.display_summary(summary)
        self.completed_pill.setText("COMPLETED")
        self.completed_pill.setProperty("state", "success")
        self.completed_meta.setText(
            f"{summary.get('mode', '')} · {summary.get('duration', 0):.1f}s · "
            f"{summary.get('pages_crawled', 0)} pages")
        self._restyle(self.completed_pill)
        self._set_state(self.STATE_COMPLETED)

    def on_scan_failed(self, message: str) -> None:
        self._stop_elapsed()
        self._active_log_view().append_log("error", f"Scan failed: {message}")
        self.stage_label.setText("Scan failed")
        self.progress_bar.setProperty("danger", True)
        self._restyle(self.progress_bar)
        self._set_state(self.STATE_SETUP)

    def on_scan_cancelled(self) -> None:
        self._stop_elapsed()
        self.stage_label.setText("Scan cancelled")
        self._running_logs.append_log("warning", "Scan was cancelled by the user")
        self._reset_to_setup()

    # ------------------------------------------------------------- helpers
    def _stop_elapsed(self) -> None:
        self._elapsed_timer.stop()
        elapsed = time.monotonic() - self._scan_start_wall if self._scan_start_wall else 0.0
        self.elapsed_label.setText(f"{elapsed:.1f}s")
        self.remaining_label.setText("")

    def _tick_elapsed(self) -> None:
        elapsed = time.monotonic() - self._scan_start_wall
        self.elapsed_label.setText(f"{elapsed:.1f}s")
        progress = self._last_progress
        if progress > 0:
            remaining = elapsed / progress * (100 - progress)
            self.remaining_label.setText(f"Estimated remaining: {remaining:.0f}s")

    @staticmethod
    def _restyle(widget: QWidget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.summary_view.apply_palette(palette)
