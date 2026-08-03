"""
Theme definitions (QSS) for the SEA scanner GUI.

Design language: professional cybersecurity tooling in the class of JetBrains
IDEs, Docker Desktop, Postman and VS Code. Flat surfaces, an indigo accent and
a report-aligned severity scale, matching the design system introduced with the
professional HTML report (v4.12.1). No neon, no gradients, no emoji.

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
    # --- report-aligned severity scale ----------------------------------
    sev_critical: str
    sev_high: str
    sev_medium: str
    sev_low: str
    sev_safe: str


DARK = Palette(
    name="dark",
    window="#0B1220",
    surface="#101A2E",
    card="#121C33",
    input="#1A2A47",
    hover="#1E2C49",
    border="#1E2C49",
    border_strong="#2B3D63",
    text="#E6ECF7",
    subtext="#93A0B5",
    muted="#64748B",
    accent="#4F46E5",
    accent_hover="#6C63F0",
    accent_pressed="#4338CA",
    success="#0E9F6E",
    warning="#D97706",
    danger="#E5484D",
    info="#0EA5E9",
    selection="#2A3A5C",
    shadow="#000000",
    rail="#0D1626",
    header="#0D1626",
    statusbar="#0D1626",
    accent_soft="#1E2447",
    success_soft="#0F2B22",
    warning_soft="#2B2410",
    danger_soft="#3A1D20",
    info_soft="#0F2733",
    sev_critical="#E5484D",
    sev_high="#F76B15",
    sev_medium="#F5A623",
    sev_low="#2E9E5B",
    sev_safe="#0E9F6E",
)

LIGHT = Palette(
    name="light",
    window="#EEF2F7",
    surface="#FFFFFF",
    card="#FFFFFF",
    input="#F0F4FA",
    hover="#E9EEF6",
    border="#E4E9F1",
    border_strong="#C9D3E0",
    text="#0F172A",
    subtext="#334155",
    muted="#64748B",
    accent="#4F46E5",
    accent_hover="#5B54E8",
    accent_pressed="#3B35C2",
    success="#0E9F6E",
    warning="#D97706",
    danger="#E5484D",
    info="#0EA5E9",
    selection="#E6E9FF",
    shadow="#C9D3E0",
    rail="#E8ECF4",
    header="#FFFFFF",
    statusbar="#FFFFFF",
    accent_soft="#E7E9FF",
    success_soft="#E2F5EE",
    warning_soft="#FDF1E0",
    danger_soft="#FDE9E9",
    info_soft="#E3F3FB",
    sev_critical="#E5484D",
    sev_high="#F76B15",
    sev_medium="#F5A623",
    sev_low="#2E9E5B",
    sev_safe="#0E9F6E",
)


def palette_for(theme: str) -> Palette:
    return LIGHT if theme == "light" else DARK


def qcolor(hex_value: str) -> QColor:
    return QColor(hex_value)


def severity_color(severity: str, palette: Palette) -> str:
    severity = (severity or "").lower()
    if severity == "critical":
        return palette.sev_critical
    if severity == "high":
        return palette.sev_high
    if severity == "medium":
        return palette.sev_medium
    if severity == "low":
        return palette.sev_low
    if severity == "warning":
        return palette.warning
    if severity == "info":
        return palette.info
    if severity in ("safe", "none", "pass"):
        return palette.success
    return palette.subtext


def severity_soft_color(severity: str, palette: Palette) -> QColor:
    """A translucent wash derived from the severity colour, for chip badges."""
    strong = severity_color(severity, palette)
    color = QColor(strong)
    color.setAlphaF(0.14)
    return color


def status_color(status: str, palette: Palette) -> str:
    status = (status or "").lower()
    if status in ("fail", "vulnerable", "error", "failed"):
        return palette.danger
    if status in ("warning", "skipped"):
        return palette.warning
    if status in ("pass", "safe", "passed"):
        return palette.success
    if status == "info":
        return palette.info
    return palette.subtext


def tier_color(tier: str, palette: Palette) -> str:
    tier = (tier or "").lower()
    if tier == "critical":
        return palette.sev_critical
    if tier == "high":
        return palette.sev_high
    if tier == "medium":
        return palette.sev_medium
    if tier == "low":
        return palette.sev_low
    if tier in ("info", "none"):
        return palette.success
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
QLabel[muted="true"] {{ color: {p.subtext}; }}
QLabel[small="true"] {{ font-size: 12px; }}
QLabel[title="true"] {{
    font-size: 22px;
    font-weight: 700;
}}
QLabel[subtitle="true"] {{
    font-size: 13px;
    color: {p.subtext};
}}
QLabel[kicker="true"] {{
    font-size: 10.5px;
    font-weight: 700;
    color: {p.muted};
}}

/* ---------- Buttons ---------- */
QPushButton {{
    background-color: {p.input};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 7px 16px;
    font-weight: 600;
}}
QPushButton:hover {{
    background-color: {p.hover};
    border-color: {p.border_strong};
}}
QPushButton:pressed {{ background-color: {p.card}; }}
QPushButton:focus {{ border-color: {p.accent}; }}
QPushButton:disabled {{
    color: {p.muted};
    background-color: {p.input};
    border-color: {p.border};
}}

QPushButton#primaryButton {{
    background-color: {p.accent};
    color: #FFFFFF;
    border: none;
    padding: 9px 20px;
    border-radius: 8px;
    font-weight: 700;
}}
QPushButton#primaryButton:hover {{ background-color: {p.accent_hover}; }}
QPushButton#primaryButton:pressed {{ background-color: {p.accent_pressed}; }}
QPushButton#primaryButton:focus {{ border: 2px solid {p.accent_hover}; }}
QPushButton#primaryButton:disabled {{
    background-color: {p.input};
    color: {p.muted};
    border: 1px solid {p.border};
}}

QPushButton#dangerButton {{
    background-color: transparent;
    color: {p.danger};
    border: 1px solid {p.danger};
    border-radius: 8px;
    padding: 9px 20px;
    font-weight: 700;
}}
QPushButton#dangerButton:hover {{ background-color: {p.danger_soft}; }}

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
    border-radius: 8px;
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
    color: {p.text};
}}
QLabel#brandSub {{
    font-size: 11px;
    font-weight: 700;
    color: {p.accent};
}}
QPushButton#headerButton {{
    background-color: transparent;
    color: {p.subtext};
    border: 1px solid transparent;
    border-radius: 8px;
    padding: 7px 12px;
    font-weight: 600;
}}
QPushButton#headerButton:hover {{
    color: {p.text};
    background-color: {p.hover};
    border-color: {p.border};
}}
QPushButton#headerButton:focus {{
    border-color: {p.accent};
    color: {p.text};
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
    border-radius: 9px;
    padding: 9px 6px;
}}
QPushButton#railButton:hover {{
    color: {p.text};
    background-color: {p.hover};
}}
QPushButton#railButton:focus {{
    border: 1px solid {p.accent};
    border-radius: 9px;
}}
QPushButton#railButton:checked {{
    color: {p.accent};
    background-color: {p.accent_soft};
}}

/* ---------- Cards / panels ---------- */
QFrame#card {{
    background-color: {p.card};
    border: 1px solid {p.border};
    border-radius: 12px;
}}
QFrame#cardHover {{
    background-color: {p.card};
    border: 1px solid {p.border_strong};
    border-radius: 12px;
}}
QFrame#panel {{
    background-color: {p.surface};
    border: 1px solid {p.border};
    border-radius: 12px;
}}

QLabel#cardTitle {{ font-size: 14px; font-weight: 700; }}
QLabel#cardSub {{ font-size: 12px; color: {p.subtext}; }}
QLabel#kpiValue {{
    font-size: 30px;
    font-weight: 700;
}}
QLabel#kpiCaption {{ font-size: 12px; color: {p.muted}; }}
QLabel#kpiIcon {{
    background-color: {p.accent_soft};
    border-radius: 9px;
}}

/* ---------- Section headers ---------- */
QLabel#sectionTitle {{ font-size: 18px; font-weight: 700; }}
QLabel#sectionSub {{ font-size: 13px; color: {p.subtext}; }}

/* ---------- Inputs ---------- */
QLineEdit, QSpinBox, QComboBox, QDoubleSpinBox {{
    background-color: {p.input};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 7px 10px;
    color: {p.text};
    selection-background-color: {p.accent};
    selection-color: #FFFFFF;
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QDoubleSpinBox:focus {{
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
    border-radius: 9px;
}}
QPushButton#segmentButton {{
    background-color: transparent;
    border: none;
    border-radius: 7px;
    padding: 6px 16px;
    color: {p.subtext};
    font-weight: 600;
}}
QPushButton#segmentButton:hover {{ color: {p.text}; }}
QPushButton#segmentButton:checked {{
    background-color: {p.card};
    color: {p.accent};
    border: 1px solid {p.border_strong};
}}

/* ---------- Progress bar ---------- */
QProgressBar {{
    background-color: {p.input};
    border: 1px solid {p.border};
    border-radius: 6px;
    text-align: center;
    color: {p.subtext};
    height: 8px;
    font-size: 11px;
}}
QProgressBar::chunk {{
    background-color: {p.accent};
    border-radius: 5px;
}}
QProgressBar::chunk[danger="true"] {{ background-color: {p.danger}; }}
QProgressBar::chunk[success="true"] {{ background-color: {p.success}; }}

/* ---------- Stage stepper ---------- */
QLabel#stepLabel {{
    font-size: 12px;
    font-weight: 600;
    color: {p.muted};
}}
QLabel#stepLabel[stepState="active"] {{ color: {p.text}; font-weight: 700; }}
QLabel#stepLabel[stepState="done"] {{ color: {p.subtext}; }}
QFrame#stepDot {{
    background-color: {p.input};
    border: 1px solid {p.border_strong};
    border-radius: 7px;
}}
QFrame#stepDot[stepState="done"] {{
    background-color: {p.accent};
    border-color: {p.accent};
}}
QFrame#stepDot[stepState="active"] {{
    background-color: {p.accent_soft};
    border: 2px solid {p.accent};
}}
QFrame#stepLine {{
    background-color: {p.input};
}}
QFrame#stepLine[lineState="done"] {{ background-color: {p.accent}; }}

/* ---------- Risk meter ---------- */
QFrame#riskMeter {{
    background-color: {p.card};
    border: 1px solid {p.border};
    border-radius: 12px;
}}
QLabel#riskScore {{
    font-size: 42px;
    font-weight: 800;
}}
QLabel#riskTier {{
    font-size: 12px;
    font-weight: 800;
}}
QLabel#riskSub {{ font-size: 12px; color: {p.muted}; }}
QLabel#riskScaleTick {{ font-size: 10px; color: {p.muted}; }}

QLabel#errorBanner {{
    background-color: {p.danger_soft};
    border: 1px solid {p.danger};
    border-radius: 10px;
    padding: 10px 14px;
    color: {p.danger};
    font-size: 12.5px;
    font-weight: 600;
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
QLabel#pill[state="idle"] {{ color: {p.muted}; }}

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
    border-radius: 10px;
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
    font-size: 11.5px;
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
    border-radius: 10px;
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
QStatusBar QLabel {{ color: {p.subtext}; padding: 2px 6px; }}
QLabel#statusLabel {{ color: {p.text}; font-weight: 600; font-size: 12px; }}
QLabel#statusLabel[state="scanning"] {{ color: {p.info}; }}
QLabel#statusLabel[state="completed"] {{ color: {p.success}; }}
QLabel#statusLabel[state="failed"] {{ color: {p.danger}; }}
QLabel#versionLabel {{ color: {p.muted}; font-size: 12px; }}

/* ---------- Toast ---------- */
QFrame#toast {{
    background-color: {p.surface};
    border: 1px solid {p.border_strong};
    border-radius: 10px;
}}
QLabel#toastTitle {{ font-weight: 700; font-size: 13px; }}
QLabel#toastBody {{ color: {p.subtext}; font-size: 12px; }}

/* ---------- Scrollbars ---------- */
QScrollBar:vertical {{
    background: transparent;
    width: 9px;
    margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: {p.border_strong};
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {p.muted}; }}
QScrollBar:horizontal {{
    background: transparent;
    height: 9px;
    margin: 2px;
}}
QScrollBar::handle:horizontal {{
    background: {p.border_strong};
    border-radius: 4px;
    min-width: 30px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

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
QMenu::item {{ padding: 6px 22px; border-radius: 6px; }}
QMenu::item:selected {{ background-color: {p.selection}; }}
QMenu::separator {{
    height: 1px;
    background: {p.border};
    margin: 4px 8px;
}}
QSplitter::handle {{ background-color: {p.border}; }}

QToolButton {{
    background-color: {p.input};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 6px 12px;
    color: {p.text};
}}
QToolButton:hover {{ background-color: {p.hover}; }}
"""


def apply_theme(app: QApplication, theme: str) -> Palette:
    palette = palette_for(theme)
    app.setStyle("Fusion")
    app.setStyleSheet(build_qss(palette))
    return palette
