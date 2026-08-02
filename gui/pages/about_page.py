"""
About page — application identity and engine credits.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from gui.resources import icons
from gui.resources.styles import DARK, Palette
from gui.version import APP_NAME, ENGINE_VERSION, GUI_VERSION
from gui.widgets.cards import PanelCard, SectionCard


class AboutPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._palette = DARK

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(32, 28, 32, 28)
        body_layout.setSpacing(18)

        header = QHBoxLayout()
        header.setSpacing(18)
        logo_label = QLabel()
        logo_label.setPixmap(icons.icon_logo(64).pixmap(64, 64))
        header.addWidget(logo_label)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        name = QLabel(APP_NAME)
        name.setObjectName("sectionTitle")
        title_col.addWidget(name)
        version = QLabel(f"Desktop GUI v{GUI_VERSION} · Engine v{ENGINE_VERSION}")
        version.setProperty("muted", True)
        title_col.addWidget(version)
        header.addLayout(title_col)
        header.addStretch(1)
        body_layout.addLayout(header)

        info = PanelCard("Product")
        intro = QLabel(
            "Enterprise-grade modular web security assessment tool with 19 scanners, "
            "multi-pass verification, response analysis, cross-finding correlation, "
            "and professional reporting — now with a native desktop interface.")
        intro.setWordWrap(True)
        info.body().addWidget(intro)
        body_layout.addWidget(info)

        tech = PanelCard("Technology")
        details = QLabel(
            "<b>Interface</b>: PySide6 (Qt 6)<br>"
            f"<b>Scanning engine</b>: SEA Scan Engine v{ENGINE_VERSION} (19 modules)<br>"
            "<b>Reporting</b>: HTML, JSON, Markdown, CSV, TXT, PDF (future-ready)<br>"
            "<b>Detection</b>: SQLi, XSS, SSRF, LFI, SSTI, CSRF, CORS, Open Redirect, "
            "Host Header, HTTP Methods, Headers, Cookies, TLS, DNS, Open Ports, "
            "Security.txt, Source Leaks, Tech Detection, Sensitive Files")
        details.setWordWrap(True)
        details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        tech.body().addWidget(details)
        body_layout.addWidget(tech)

        note = PanelCard("Note")
        note_text = QLabel(
            "The GUI is a presentation layer over the existing scanning engine. "
            "No detection logic, scoring, or report generation was modified.")
        note_text.setWordWrap(True)
        note_text.setProperty("muted", True)
        note.body().addWidget(note_text)
        body_layout.addWidget(note)

        body_layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(body)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(scroll)

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
