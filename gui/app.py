"""
Application bootstrap — creates the QApplication, applies the theme, and shows
the main window.
"""

import logging
import sys

from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication

from gui import APP_NAME, ORGANIZATION
from gui.main_window import MainWindow
from gui.resources.styles import apply_theme
from gui.services.settings_store import SettingsStore


def _system_theme() -> str:
    try:
        scheme = QGuiApplication.styleHints().colorScheme()
        if str(scheme).lower().endswith("dark"):
            return "dark"
    except Exception:
        pass
    return "light"


def run_gui(argv=None) -> int:
    if argv is None:
        argv = sys.argv

    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setOrganizationName(ORGANIZATION)

    settings = SettingsStore()
    theme = settings.get("theme")
    if theme == "system":
        theme = _system_theme()
    apply_theme(app, theme)

    window = MainWindow(settings)
    window.show()
    return app.exec()


def main() -> None:
    sys.exit(run_gui())


if __name__ == "__main__":
    main()
