"""
MainWindow — left icon rail, top bar with brand + global New Scan action,
central page stack, bottom status bar and corner toast host.
"""

import logging
import os

from PySide6.QtCore import QSize, QUrl, Qt
from PySide6.QtGui import QCloseEvent, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from gui import APP_NAME, GUI_VERSION
from gui.controllers.scan_controller import ScanController
from gui.pages.about_page import AboutPage
from gui.pages.history_page import HistoryPage
from gui.pages.overview_page import OverviewPage
from gui.pages.scanner_page import ScannerPage
from gui.pages.settings_page import SettingsPage
from gui.resources import icons
from gui.resources.styles import Palette, apply_theme
from gui.services.history_store import HistoryStore
from gui.services.qt_log_handler import QtLogBridge, QtLogHandler
from gui.services.settings_store import SettingsStore
from gui.version import ENGINE_VERSION
from gui.widgets.brand import BrandHeader
from gui.widgets.toast import ToastHost

logger = logging.getLogger("SeaScanner.GUI.MainWindow")

PAGES = ("overview", "scanner", "history", "settings", "about")


class MainWindow(QMainWindow):
    def __init__(self, settings_store: SettingsStore = None):
        super().__init__()
        self.settings_store = settings_store or SettingsStore()
        self.history_store = HistoryStore()
        self.controller = ScanController(self)
        self.log_bridge = QtLogBridge(self)
        self._log_handler = QtLogHandler.install(self.log_bridge, level=logging.INFO)

        self.setWindowTitle(APP_NAME)
        self.resize(1280, 820)
        self.setMinimumSize(1024, 680)

        self._build_ui()
        self._wire_controller()
        self._theme = self.settings_store.get("theme")
        self._palette = apply_theme(
            QApplication.instance(), self._resolve_theme(self._theme))

        self.navigate("overview")
        self.show_toast("Welcome", "SEA Corporate Security Scanner is ready.", "info", 3500)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_rail())
        body.addWidget(self._build_pages(), 1)
        root.addLayout(body, 1)

        self.setCentralWidget(central)
        self._build_status_bar()

        self.toast_host = ToastHost(self)
        self.toast_host.move(0, 0)

    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setObjectName("header")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(6)

        self.brand_header = BrandHeader()
        layout.addWidget(self.brand_header)

        layout.addStretch(1)

        self.header_status = QLabel()
        self.header_status.setObjectName("pill")
        self.header_status.setProperty("state", "idle")
        self.header_status.setText("READY")
        layout.addWidget(self.header_status)

        layout.addSpacing(12)

        self.new_scan_btn = QToolButton()
        self.new_scan_btn.setObjectName("headerButton")
        self.new_scan_btn.setText("  New Scan")
        self.new_scan_btn.setIcon(icons.icon_plus())
        self.new_scan_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.new_scan_btn.clicked.connect(lambda: self.navigate("scanner"))
        layout.addWidget(self.new_scan_btn)
        return header

    def _build_rail(self) -> QWidget:
        rail = QWidget()
        rail.setObjectName("rail")
        rail.setFixedWidth(64)
        layout = QVBoxLayout(rail)
        layout.setContentsMargins(8, 12, 8, 12)
        layout.setSpacing(4)

        self._rail_buttons = {}
        self._rail_icon_fns = {}
        specs = [
            ("overview", "Overview", icons.icon_overview),
            ("scanner", "Scanner", icons.icon_scanner),
            ("history", "History", icons.icon_history),
            ("settings", "Settings", icons.icon_settings),
            ("about", "About", icons.icon_about),
        ]
        for key, label, icon_fn in specs:
            btn = QToolButton()
            btn.setObjectName("railButton")
            btn.setIconSize(QSize(20, 20))
            btn.setFixedSize(48, 44)
            btn.setToolTip(label)
            btn.setCheckable(True)
            btn.setAutoRaise(True)
            btn.clicked.connect(lambda _checked=False, k=key: self.navigate(k))
            layout.addWidget(btn, 0, Qt.AlignmentFlag.AlignHCenter)
            self._rail_buttons[key] = btn
            self._rail_icon_fns[key] = icon_fn

        layout.addStretch(1)
        return rail

    def _build_pages(self) -> QStackedWidget:
        self.stack = QStackedWidget()
        self.overview_page = OverviewPage(
            self.settings_store, self.history_store, self.controller)
        self.scanner_page = ScannerPage(self.controller, self.settings_store)
        self.history_page = HistoryPage(self.history_store)
        self.settings_page = SettingsPage(self.settings_store)
        self.about_page = AboutPage()

        for page in (self.overview_page, self.scanner_page, self.history_page,
                     self.settings_page, self.about_page):
            self.stack.addWidget(page)
        return self.stack

    def _build_status_bar(self) -> None:
        bar = QStatusBar()
        self.setStatusBar(bar)
        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("statusLabel")
        bar.addWidget(self.status_label, 1)
        self.version_label = QLabel(f"v{GUI_VERSION} · Engine {ENGINE_VERSION}")
        self.version_label.setObjectName("versionLabel")
        bar.addPermanentWidget(self.version_label)

    # -------------------------------------------------------------- wiring
    def _wire_controller(self) -> None:
        c = self.controller
        c.scan_started.connect(self._on_scan_started)
        c.scan_finished.connect(self._on_scan_finished)
        c.scan_failed.connect(self._on_scan_failed)
        c.scan_cancelled.connect(self._on_scan_cancelled)
        c.progress.connect(self.scanner_page.on_progress)
        c.stage_changed.connect(self.scanner_page.on_stage)
        c.stage_changed.connect(self._on_stage)
        c.module_started.connect(self.scanner_page.on_module_started)
        c.module_finished.connect(self.scanner_page.on_module_finished)
        c.log.connect(self.scanner_page.on_log)
        self.log_bridge.log_message.connect(self.scanner_page.on_log)

        self.overview_page.new_scan_requested.connect(
            lambda: self.navigate("scanner"))
        self.overview_page.open_history_requested.connect(
            lambda: self.navigate("history"))
        self.overview_page.open_latest_report.connect(self._open_latest_report)
        self.settings_page.settings_saved.connect(self._on_settings_saved)
        self.scanner_page.scan_requested.connect(
            lambda: self.navigate("scanner"))

    # ---------------------------------------------------------- navigation
    def navigate(self, page: str) -> None:
        if page not in PAGES:
            page = "overview"
        index = PAGES.index(page)
        self.stack.setCurrentIndex(index)
        for key, btn in self._rail_buttons.items():
            btn.setChecked(PAGES.index(key) == index)
        if hasattr(self, "_palette"):
            self._apply_rail_icons(self._palette)
        if page == "overview":
            self.overview_page.refresh()
        elif page == "history":
            self.history_page.refresh()

    def _quick_scan(self, mode: str) -> None:
        self.scanner_page.set_mode(mode)
        self.navigate("scanner")

    # -------------------------------------------------------------- status
    def set_status(self, text: str, state: str = "idle") -> None:
        self.status_label.setText(text)
        self.status_label.setProperty("state", state)
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

        self.header_status.setText({"scanning": "SCANNING", "completed": "COMPLETED",
                                    "failed": "FAILED", "cancelled": "CANCELLED",
                                    "idle": "READY"}.get(state, "READY"))
        self.header_status.setProperty("state", {
            "scanning": "info", "completed": "success", "failed": "danger",
            "cancelled": "danger", "idle": "idle"}.get(state, "idle"))
        self.header_status.style().unpolish(self.header_status)
        self.header_status.style().polish(self.header_status)

    def _on_stage(self, stage: str) -> None:
        self.set_status(stage, "scanning")

    def _on_scan_started(self) -> None:
        self.set_status("Scanning...", "scanning")
        self.navigate("scanner")

    def _on_scan_finished(self, summary: dict) -> None:
        self.set_status("Completed", "completed")
        entry = {
            "target": summary.get("target", ""),
            "started": summary.get("started", ""),
            "duration": round(summary.get("duration", 0), 1),
            "mode": summary.get("mode", ""),
            "risk_score": summary.get("risk_score", 0),
            "overall_severity": summary.get("overall_severity", ""),
            "overall_color": summary.get("overall_color", ""),
            "overall_tier": summary.get("overall_tier", "none"),
            "report_paths": summary.get("report_paths", []),
            "vulnerabilities": summary.get("vulnerabilities", 0),
            "coverage": summary.get("coverage", 0),
        }
        self.history_store.add_scan(entry)
        self.overview_page.refresh()
        self.history_page.refresh()
        self.scanner_page.on_scan_finished(summary)

        auto_open = self.settings_store.get("auto_open_report")
        if auto_open and summary.get("report_paths"):
            self._open_path(summary["report_paths"][0])

        self.show_toast(
            "Scan completed",
            f"{summary.get('target', '')} — {summary.get('overall_severity', 'No Risk')}",
            "success", 5200)

    def _on_scan_failed(self, message: str) -> None:
        self.set_status("Failed", "failed")
        self.scanner_page.on_scan_failed(message)
        self.show_toast("Scan failed", message, "danger", 6000)

    def _on_scan_cancelled(self) -> None:
        self.set_status("Cancelled", "cancelled")
        self.scanner_page.on_scan_cancelled()
        self.show_toast("Scan cancelled", "The scan was stopped by the user.", "warning", 4500)

    def _on_settings_saved(self) -> None:
        theme = self.settings_store.get("theme")
        self._apply_theme_to_app(theme)
        self.show_toast("Settings saved", "Preferences updated.", "success", 3000)

    # ------------------------------------------------------------- toasts
    def show_toast(self, title: str, body: str = "", level: str = "info",
                   duration_ms: int = 4200) -> None:
        self.toast_host.show_toast(title, body, level, duration_ms)

    # --------------------------------------------------------------- theme
    def _resolve_theme(self, theme: str) -> str:
        if theme == "system":
            try:
                from PySide6.QtGui import QGuiApplication
                scheme = QGuiApplication.styleHints().colorScheme()
                if str(scheme).lower().endswith("dark"):
                    return "dark"
                return "light"
            except Exception:
                return "dark"
        return theme

    def _apply_theme_to_app(self, theme: str) -> None:
        self._theme = theme
        self._palette = apply_theme(
            QApplication.instance(), self._resolve_theme(theme))
        self._apply_palette_to_pages(self._palette)
        self.toast_host.apply_palette(self._palette)

    def _apply_palette_to_pages(self, palette) -> None:
        for page in (self.overview_page, self.scanner_page, self.history_page,
                     self.settings_page, self.about_page):
            if hasattr(page, "apply_palette"):
                page.apply_palette(palette)
        self._apply_rail_icons(palette)
        self.brand_header.apply_palette(palette)

    def _apply_rail_icons(self, palette: Palette) -> None:
        for key, btn in self._rail_buttons.items():
            idx = PAGES.index(key)
            active = self.stack.currentIndex() == idx
            color = palette.accent if active else palette.subtext
            btn.setIcon(self._rail_icon_fns[key](20, color))

    # ---------------------------------------------------------------- misc
    def _open_latest_report(self) -> None:
        last = self.history_store.get_last()
        if not last:
            return
        paths = last.get("report_paths") or []
        if paths:
            self._open_path(paths[0])
        else:
            self.navigate("scanner")

    @staticmethod
    def _open_path(path: str) -> None:
        if os.path.exists(path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.controller.running:
            self.controller.shutdown(wait_ms=3000)
        event.accept()
