"""
Application settings — persisted as JSON in the user data directory.

Loads lazily on first access; ``save()`` writes atomically.
"""

import json
import logging
import os
import tempfile

from gui.services import paths

logger = logging.getLogger("SeaScanner.GUI.Settings")

DEFAULTS = {
    "theme": "dark",                     # system | dark | light
    "default_scan_mode": "standard",     # quick | standard | deep
    "default_thread_count": 5,
    "default_timeout": 15,
    "default_report_dir": "",
    "auto_open_report": False,
    "remember_last_target": True,
    "last_target": "",
    "output_html": True,
    "output_pdf": False,
}

_VALID_MODES = ("quick", "standard", "deep")


class SettingsStore:
    def __init__(self, path: str = None):
        self.path = path or paths.settings_path()
        self._data = dict(DEFAULTS)
        self.load()

    def load(self) -> None:
        try:
            if os.path.exists(self.path):
                with open(self.path, "r", encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, dict):
                    self._data.update({k: v for k, v in loaded.items() if k in DEFAULTS})
        except Exception as exc:
            logger.warning("Could not load settings: %s", exc)

    def save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, ensure_ascii=False)
            os.replace(tmp, self.path)
        except Exception as exc:
            logger.error("Could not save settings: %s", exc)

    def get(self, key: str, default=None):
        return self._data.get(key, default if default is not None else DEFAULTS.get(key))

    def set(self, key: str, value) -> None:
        self._data[key] = value

    def update(self, values: dict) -> None:
        for key, value in values.items():
            if key in DEFAULTS:
                self._data[key] = value

    def all(self) -> dict:
        return dict(self._data)

    def sanitize_mode(self, mode: str) -> str:
        return mode if mode in _VALID_MODES else "standard"
