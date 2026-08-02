"""
Scrolling log viewer for the Scan page — timestamped, severity-colored,
auto-scrolls, and supports clear / save.
"""

import logging
import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import QPlainTextEdit

from gui.resources import styles
from gui.resources.styles import Palette

logger = logging.getLogger("SeaScanner.GUI.LogView")

LEVEL_ORDER = {"error": 0, "warning": 1, "info": 2, "debug": 3}


class LogView(QPlainTextEdit):
    def __init__(self, parent=None, max_blocks: int = 8000):
        super().__init__(parent)
        self.setObjectName("logView")
        self.setReadOnly(True)
        self.setMaximumBlockCount(max_blocks)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._palette = styles.DARK

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette

    def append_log(self, level: str, message: str) -> None:
        palette = self._palette
        timestamp_color = QColor(palette.muted)
        level = (level or "info").lower()
        if level not in LEVEL_ORDER:
            level = "info"

        level_color = {
            "error": styles.qcolor(palette.danger),
            "warning": styles.qcolor(palette.warning),
            "info": styles.qcolor(palette.info),
            "debug": styles.qcolor(palette.muted),
        }[level]
        message_color = QColor(palette.subtext) if level == "debug" else QColor(palette.text)

        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.setTextCursor(cursor)

        ts = time.strftime("%H:%M:%S")

        ts_fmt = QTextCharFormat()
        ts_fmt.setForeground(timestamp_color)
        cursor.insertText(f"[{ts}] ", ts_fmt)

        lvl_fmt = QTextCharFormat()
        lvl_fmt.setForeground(level_color)
        lvl_fmt.setFontWeight(700)
        cursor.insertText(f"{level.upper():<7}", lvl_fmt)

        msg_fmt = QTextCharFormat()
        msg_fmt.setForeground(message_color)
        cursor.insertText(f" {message}\n", msg_fmt)

        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def clear_logs(self) -> None:
        self.clear()

    def save_to_file(self, path: str) -> bool:
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.toPlainText())
            return True
        except OSError as exc:
            logger.error("Could not save logs: %s", exc)
            return False
