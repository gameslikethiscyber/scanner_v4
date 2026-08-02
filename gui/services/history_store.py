"""
Scan history — JSON-backed store of real scan summaries for the dashboard.

No fake statistics: every entry is written when a scan actually completes.
"""

import json
import logging
import os
import tempfile

from gui.services import paths

logger = logging.getLogger("SeaScanner.GUI.History")

MAX_ENTRIES = 100


class HistoryStore:
    def __init__(self, path: str = None, max_entries: int = MAX_ENTRIES):
        self.path = path or paths.history_path()
        self.max_entries = max_entries
        self._scans: list = []
        self.load()

    def load(self) -> None:
        try:
            if os.path.exists(self.path):
                with open(self.path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                self._scans = data.get("scans", []) if isinstance(data, dict) else []
        except Exception as exc:
            logger.warning("Could not load history: %s", exc)
            self._scans = []

    def save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"scans": self._scans}, fh, indent=2, ensure_ascii=False)
            os.replace(tmp, self.path)
        except Exception as exc:
            logger.error("Could not save history: %s", exc)

    def add_scan(self, entry: dict) -> None:
        self._scans.append(entry)
        if len(self._scans) > self.max_entries:
            self._scans = self._scans[-self.max_entries:]
        self.save()

    def get_all(self) -> list:
        return list(self._scans)

    def get_last(self) -> dict | None:
        return self._scans[-1] if self._scans else None

    def recent_targets(self, limit: int = 6) -> list:
        seen = []
        for scan in reversed(self._scans):
            target = scan.get("target", "")
            if target and target not in seen:
                seen.append(target)
            if len(seen) >= limit:
                break
        return seen

    def total_scans(self) -> int:
        return len(self._scans)
