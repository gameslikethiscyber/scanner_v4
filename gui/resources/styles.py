"""
Theme definitions (QSS) for the SEA scanner GUI.

Design language: enterprise security tooling (Burp Suite Pro / Postman /
Docker Desktop grade). Near-black navy surfaces with an electric-blue accent,
segmented navigation rail, KPI cards, risk meter and toast components.

Two complete palettes (dark / light) plus helpers used across the UI.
"""

from dataclasses import dataclass

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QApplication


@dataclass(frozen=True)
class Palette:
    name: str
    window: str
    surface: str
    card: str
    input: str
    hover: str
    border: str
    border_strong: str
    text: str
    subtext: str
    muted: str
    accent: str
    accent_hover: str
    accent_pressed: str
    success: str
    warning: str
    danger: str
    info: str
    selection: str
    shadow: str
    # --- design-system extras -------------------------------------------
    rail: str            # left navigation rail background
    header: str          # top bar background
    statusbar: str       # bottom status bar background
    accent_soft: str     # translucent accent wash for active items
    success_soft: str
    warning_soft: str
    danger_soft: str
    info_soft: str


DARK = Palette(
    name="dark",
    window="#0b0e14",
    surface="#12161f",
    card="#151a26",
    input="#1a2030",
    hover="#202839",
    border="#232b3c",
    border_strong="#32405a",
    text="#e8ecf4",
    subtext="#93a0b5",
    muted="#5c6b82",
    accent="#2e7cf6",
    accent_hover="#4a8fff",
    accent_pressed="#1e66de",
    success="#34d399",
    warning="#fbbf24",
    danger="#f87171",
    info="#38bdf8",
    selection="#1e2c47",
    shadow="#000000",
    rail="#0e1220",
    header="#0e1220",
    statusbar="#0e1220",
    accent_soft="#16253f",
    success_soft="#0f2b22",
    warning_soft="#2b2410",
    danger_soft="#2c1718",
    info_soft="#0f2733",
)

LIGHT = Palette(
    name="light",
    window="#f4f6fa",
    surface="#ffffff",
    card="#ffffff",
    input="#eef1f6",
    hover="#e6ebf3",
    border="#d6dee9",
    border_strong="#b9c5d4",
    text="#16233b",
    subtext="#51607a",
    muted="#8a97ac",
    accent="#1e66de",
    accent_hover="#2e7cf6",
    accent_pressed="#164fa8",
    success="#0f9d6e",
    warning="#b45309",
    danger="#dc2626",
    info="#0284c7",
    selection="#dbe8fc",
    shadow="#d6dee9",
    rail="#eef1f6",
    header="#ffffff",
    statusbar="#ffffff",
    accent_soft="#e5effd",
    success_soft="#e2f5ee",
    warning_soft="#fdf1e0",
    danger_soft="#fdeaea",
    info_soft="#e3f3fb",
)


def palette_for(theme: str) -> Palette:
    return LIGHT if theme == "light" else DARK


def qcolor(hex_value: str) -> QColor:
    return QColor(hex_value)


def severity_color(severity: str, palette: Palette) -> str:
    severity = (severity or "").lower()
    if severity in ("critical", "high"):
        return palette.danger
    if severity == "medium":
        return palette.warning
    if severity in ("low", "warning"):
        return palette.success if severity == "low" else palette.warning
    if severity == "info":
        return palette.info
    return palette.subtext


def status_color(status: str, palette: Palette) -> str:
    status = (status or "").lower()
    if status in ("fail", "vulnerable", "error", "failed"):
        return palette.danger
    if status in ("warning", "skipped"):
        return palette.warning
    if status in ("pass", "safe", "info", "passed"):
        return palette.info if status == "info" else palette.success
    return palette.subtext


def tier_color(tier: str, palette: Palette) -> str:
    tier = (tier or "").lower()
    if tier in ("critical", "high"):
        return palette.danger
    if tier == "medium":
        return palette.warning
    if tier in ("low", "info"):
        return palette.info
    return palette.success


def tier_from_severity(severity: str) -> str:
    severity = (severity or "").lower()
    if severity in ("critical", "high"):
        return "high"
    if severity == "medium":
        return "medium"
    if severity in ("low", "info"):
        return "low"
    return "none"


def build_qss(palette: Palette) -> str:
    p = palette
    return f"""
* {{
    font-family: "Segoe UI", "Cantarell", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
    outline: none;
}}

QMainWindow, QDialog {{
    background-color: {p.window};
}}

QWidget {{
    background-color: transparent;
    color: {p.text};
}}

/* ---------- Labels ---------- */
QLabel {{
    color: {p.text};
    background: transparent;
}}
QLabel[muted="true"] {{
    color: {p.subtext};
}}
QLabel[small="true"] {{
    font-size: 12px;
}}
QLabel[title="true"] {{
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.2px;
}}
QLabel[subtitle="true"] {{
    font-size: 13px;
    color: {p.subtext};
}}
QLabel[kicker="true"] {{
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1.2px;
    color: {p.muted};
    text-transform: uppercase;
}}

/* ---------- Buttons ---------- */
QPushButton {{
    background-color: {p.input};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: 7px;
    padding: 7px 16px;
    font-weight: 600;
}}
QPushButton:hover {{
    background-color: {p.hover};
    border-color: {p.border_strong};
}}
QPushButton:pressed {{
    background-color: {p.card};
}}
QPushButton:disabled {{
    color: {p.muted};
    background-color: {p.input};
    border-color: {p.border};
}}

QPushButton#primaryButton {{
    background-color: {p.accent};
    color: #ffffff;
    border: none;
    padding: 9px 20px;
    border-radius: 7px;
    font-weight: 700;
}}
QPushButton#primaryButton:hover {{
    background-color: {p.accent_hover};
}}
QPushButton#primaryButton:pressed {{
    background-color: {p.accent_pressed};
}}
QPushButton#primaryButton:disabled {{
    background-color: {p.input};
    color: {p.muted};
    border: 1px solid {p.border};
}}

QPushButton#dangerButton {{
    background-color: transparent;
    color: {p.danger};
    border: 1px solid {p.danger};
    border-radius: 7px;
    padding: 9px 20px;
    font-weight: 700;
}}
QPushButton#dangerButton:hover {{
    background-color: {p.danger_soft};
}}
QPushButton#dangerButton:disabled {{
    color: {p.muted};
    border-color: {p.border};
}}

QPushButton#ghostButton {{
    background-color: transparent;
    color: {p.subtext};
    border: 1px solid {p.border};
}}
QPushButton#ghostButton:hover {{
    color: {p.text};
    background-color: {p.hover};
}}

QPushButton#iconButton {{
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 7px;
    padding: 6px;
}}
QPushButton#iconButton:hover {{
    background-color: {p.hover};
    border-color: {p.border};
}}

/* ---------- Header / top bar ---------- */
QWidget#header {{
    background-color: {p.header};
    border-bottom: 1px solid {p.border};
}}
QLabel#brandMark {{
    font-size: 15px;
    font-weight: 800;
    letter-spacing: 0.6px;
    color: {p.text};
}}
QLabel#brandSub {{
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1.4px;
    color: {p.accent};
}}
QPushButton#headerButton {{
    background-color: transparent;
    color: {p.subtext};
    border: none;
    border-radius: 7px;
    padding: 7px 12px;
    font-weight: 600;
}}
QPushButton#headerButton:hover {{
    color: {p.text};
    background-color: {p.hover};
}}

/* ---------- Left rail ---------- */
QWidget#rail {{
    background-color: {p.rail};
    border-right: 1px solid {p.border};
}}
QPushButton#railButton {{
    background-color: transparent;
    color: {p.subtext};
    border: none;
    border-radius: 8px;
    padding: 9px 6px;
}}
QPushButton#railButton:hover {{
    color: {p.text};
    background-color: {p.hover};
}}
QPushButton#railButton:checked {{
    color: {p.accent};
    background-color: {p.accent_soft};
}}

/* ---------- Cards / panels ---------- */
QFrame#card {{
    background-color: {p.card};
    border: 1px solid {p.border};
    border-radius: 10px;
}}
QFrame#cardHover {{
    background-color: {p.card};
    border: 1px solid {p.border_strong};
    border-radius: 10px;
}}
QFrame#panel {{
    background-color: {p.surface};
    border: 1px solid {p.border};
    border-radius: 10px;
}}

QLabel#cardTitle {{
    font-size: 14px;
    font-weight: 700;
}}
QLabel#cardSub {{
    font-size: 12px;
    color: {p.subtext};
}}
QLabel#kpiValue {{
    font-size: 30px;
    font-weight: 700;
    letter-spacing: -0.5px;
}}
QLabel#kpiCaption {{
    font-size: 12px;
    color: {p.muted};
}}

/* ---------- Section headers ---------- */
QLabel#sectionTitle {{
    font-size: 18px;
    font-weight: 700;
    letter-spacing: -0.2px;
}}
QLabel#sectionSub {{
    font-size: 13px;
    color: {p.subtext};
}}

/* ---------- Inputs ---------- */
QLineEdit, QSpinBox, QComboBox, QDoubleSpinBox {{
    background-color: {p.input};
    border: 1px solid {p.border};
    border-radius: 7px;
    padding: 7px 10px;
    color: {p.text};
    selection-background-color: {p.accent};
    selection-color: #ffffff;
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border-color: {p.accent};
}}
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {{
    color: {p.muted};
    background-color: {p.surface};
}}

QComboBox::drop-down {{
    border: none;
    width: 26px;
}}
QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid {p.subtext};
    margin-right: 8px;
}}
QComboBox QAbstractItemView {{
    background-color: {p.card};
    border: 1px solid {p.border};
    border-radius: 8px;
    selection-background-color: {p.selection};
    selection-color: {p.text};
    padding: 4px;
}}

QSpinBox::up-button, QSpinBox::down-button {{
    background-color: {p.input};
    border: none;
    width: 20px;
    border-radius: 4px;
}}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
    background-color: {p.hover};
}}

QCheckBox, QRadioButton {{
    spacing: 8px;
    color: {p.text};
}}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 18px;
    height: 18px;
    border: 1px solid {p.border_strong};
    border-radius: 5px;
    background-color: {p.input};
}}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
    background-color: {p.accent};
    border-color: {p.accent};
}}
QCheckBox::indicator:hover, QRadioButton::indicator:hover {{
    border-color: {p.accent};
}}

/* ---------- Segmented control ---------- */
QFrame#segmented {{
    background-color: {p.input};
    border: 1px solid {p.border};
    border-radius: 8px;
}}
QPushButton#segmentButton {{
    background-color: transparent;
    border: none;
    border-radius: 6px;
    padding: 7px 16px;
    color: {p.subtext};
    font-weight: 600;
}}
QPushButton#segmentButton:hover {{
    color: {p.text};
}}
QPushButton#segmentButton:checked {{
    background-color: {p.card};
    color: {p.text};
    border: 1px solid {p.border_strong};
}}

/* ---------- Progress bar ---------- */
QProgressBar {{
    background-color: {p.input};
    border: 1px solid {p.border};
    border-radius: 5px;
    text-align: center;
    color: {p.subtext};
    height: 8px;
    font-size: 11px;
}}
QProgressBar::chunk {{
    background-color: {p.accent};
    border-radius: 4px;
}}
QProgressBar::chunk[danger="true"] {{
    background-color: {p.danger};
}}
QProgressBar::chunk[success="true"] {{
    background-color: {p.success};
}}

/* ---------- Risk meter ---------- */
QFrame#riskMeter {{
    background-color: {p.card};
    border: 1px solid {p.border};
    border-radius: 10px;
}}
QLabel#riskScore {{
    font-size: 46px;
    font-weight: 800;
    letter-spacing: -1px;
}}
QLabel#riskTier {{
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 0.4px;
}}
QLabel#riskSub {{
    font-size: 12px;
    color: {p.muted};
}}

/* ---------- Status pill / badge ---------- */
QLabel#pill {{
    background-color: {p.input};
    border: 1px solid {p.border};
    border-radius: 999px;
    padding: 3px 10px;
    font-size: 11px;
    font-weight: 700;
    color: {p.subtext};
}}
QLabel#pill[state="success"] {{
    background-color: {p.success_soft};
    border-color: {p.success};
    color: {p.success};
}}
QLabel#pill[state="warning"] {{
    background-color: {p.warning_soft};
    border-color: {p.warning};
    color: {p.warning};
}}
QLabel#pill[state="danger"] {{
    background-color: {p.danger_soft};
    border-color: {p.danger};
    color: {p.danger};
}}
QLabel#pill[state="info"] {{
    background-color: {p.info_soft};
    border-color: {p.info};
    color: {p.info};
}}
QLabel#pill[state="idle"] {{
    color: {p.muted};
}}

QLabel#badge {{
    background-color: {p.accent_soft};
    border-radius: 6px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 700;
    color: {p.accent};
}}
QLabel#badge[danger="true"] {{
    background-color: {p.danger_soft};
    color: {p.danger};
}}

/* ---------- Lists / tables ---------- */
QListWidget, QTableWidget, QTreeWidget {{
    background-color: {p.input};
    border: 1px solid {p.border};
    border-radius: 9px;
    padding: 4px;
    color: {p.text};
}}
QListWidget::item, QTreeWidget::item {{
    padding: 7px 8px;
    border-radius: 6px;
}}
QListWidget::item:selected, QTreeWidget::item:selected {{
    background-color: {p.selection};
    color: {p.text};
}}
QListWidget::item:hover, QTreeWidget::item:hover {{
    background-color: {p.hover};
}}

QHeaderView::section {{
    background-color: {p.surface};
    color: {p.subtext};
    border: none;
    border-bottom: 1px solid {p.border};
    padding: 8px;
    font-weight: 700;
    font-size: 12px;
}}
QTableWidget {{
    gridline-color: {p.border};
}}
QTableWidget::item {{
    padding: 6px;
    border: none;
}}
QTableWidget::item:selected {{
    background-color: {p.selection};
    color: {p.text};
}}

/* ---------- Log viewer ---------- */
QPlainTextEdit#logView {{
    background-color: {p.window};
    border: 1px solid {p.border};
    border-radius: 9px;
    padding: 8px;
    color: {p.subtext};
    font-family: "Consolas", "Cascadia Mono", "Courier New", monospace;
    font-size: 12px;
}}

/* ---------- Status bar ---------- */
QStatusBar {{
    background-color: {p.statusbar};
    color: {p.subtext};
    border-top: 1px solid {p.border};
}}
QStatusBar QLabel {{
    color: {p.subtext};
    padding: 2px 6px;
}}
QLabel#statusLabel {{
    color: {p.text};
    font-weight: 600;
    font-size: 12px;
}}
QLabel#statusLabel[state="scanning"] {{
    color: {p.info};
}}
QLabel#statusLabel[state="completed"] {{
    color: {p.success};
}}
QLabel#statusLabel[state="failed"] {{
    color: {p.danger};
}}
QLabel#versionLabel {{
    color: {p.muted};
    font-size: 12px;
}}

/* ---------- Toast ---------- */
QFrame#toast {{
    background-color: {p.surface};
    border: 1px solid {p.border_strong};
    border-radius: 9px;
}}
QLabel#toastTitle {{
    font-weight: 700;
    font-size: 13px;
}}
QLabel#toastBody {{
    color: {p.subtext};
    font-size: 12px;
}}

/* ---------- Scrollbars ---------- */
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: {p.border_strong};
    border-radius: 5px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {p.muted};
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
    margin: 2px;
}}
QScrollBar::handle:horizontal {{
    background: {p.border_strong};
    border-radius: 5px;
    min-width: 30px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{
    height: 0;
    width: 0;
}}
QScrollBar::add-page, QScrollBar::sub-page {{
    background: transparent;
}}

/* ---------- Tooltips / menus / splits ---------- */
QToolTip {{
    background-color: {p.surface};
    color: {p.text};
    border: 1px solid {p.border_strong};
    border-radius: 6px;
    padding: 6px 8px;
}}
QMenu {{
    background-color: {p.surface};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 6px;
}}
QMenu::item {{
    padding: 6px 22px;
    border-radius: 6px;
}}
QMenu::item:selected {{
    background-color: {p.selection};
}}
QMenu::separator {{
    height: 1px;
    background: {p.border};
    margin: 4px 8px;
}}
QSplitter::handle {{
    background-color: {p.border};
}}

QToolButton {{
    background-color: {p.input};
    border: 1px solid {p.border};
    border-radius: 7px;
    padding: 6px 12px;
    color: {p.text};
}}
QToolButton:hover {{
    background-color: {p.hover};
}}
"""


def apply_theme(app: QApplication, theme: str) -> Palette:
    palette = palette_for(theme)
    app.setStyle("Fusion")
    app.setStyleSheet(build_qss(palette))
    return palette
