"""
Bridges Python's ``logging`` into the GUI so engine messages appear in the
live log viewer without touching the engine itself.
"""

import logging

from PySide6.QtCore import QObject, Signal


class QtLogBridge(QObject):
    log_message = Signal(str, str)  # level, message


class QtLogHandler(logging.Handler):
    LEVEL_MAP = {
        logging.CRITICAL: "error",
        logging.ERROR: "error",
        logging.WARNING: "warning",
        logging.INFO: "info",
        logging.DEBUG: "debug",
    }

    def __init__(self, bridge: QtLogBridge, level: int = logging.INFO):
        super().__init__(level=level)
        self.bridge = bridge

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
            level = self.LEVEL_MAP.get(record.levelno, "info")
            self.bridge.log_message.emit(level, message)
        except Exception:
            pass

    @classmethod
    def install(cls, bridge: QtLogBridge, level: int = logging.INFO) -> "QtLogHandler":
        handler = cls(bridge, level=level)
        handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
        root = logging.getLogger()
        root.addHandler(handler)
        if root.level == logging.WARNING or root.level == logging.NOTSET:
            root.setLevel(logging.DEBUG)
        return handler
