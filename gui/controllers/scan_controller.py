"""
ScanController — owns the worker QThread lifecycle and re-emits worker events
to the rest of the UI. The GUI thread never blocks; all engine work happens on
the worker thread.
"""

import logging
import time

from PySide6.QtCore import QObject, QThread, Signal, Slot

from gui.services.scan_worker import ScanWorker

logger = logging.getLogger("SeaScanner.GUI.Controller")


class ScanController(QObject):
    scan_started = Signal()
    scan_finished = Signal(object)      # summary dict
    scan_failed = Signal(str)
    scan_cancelled = Signal()

    stage_changed = Signal(str)
    progress = Signal(int, str)
    log = Signal(str, str)
    module_started = Signal(str, str)
    module_finished = Signal(str, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None
        self._start_time: float = 0.0
        self._last_progress: int = 0
        self.last_summary: dict | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start_time if self.running else 0.0

    @property
    def last_progress(self) -> int:
        return self._last_progress

    def start_scan(self, target: str, mode: str, thread_count: int, timeout: int,
                   outputs: dict, report_dir: str, branding: dict = None,
                   auth_spec=None, crawl: dict = None) -> bool:
        if self.running:
            return False

        self._thread = QThread(self)
        self._worker = ScanWorker(
            target=target,
            mode=mode,
            thread_count=thread_count,
            timeout=timeout,
            outputs=outputs,
            report_dir=report_dir,
            branding=branding,
            auth_spec=auth_spec,
            crawl=crawl,
        )
        self._worker.moveToThread(self._thread)

        self._worker.stage_changed.connect(self.stage_changed)
        self._worker.progress.connect(self._on_progress)
        self._worker.log.connect(self.log)
        self._worker.module_started.connect(self.module_started)
        self._worker.module_finished.connect(self.module_finished)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.cancelled.connect(self._on_cancelled)

        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._worker.cancelled.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)

        self._start_time = time.monotonic()
        self._last_progress = 0
        self._thread.start()
        self.scan_started.emit()
        logger.info("Scan started: %s (%s)", target, mode)
        return True

    def cancel_scan(self) -> None:
        if self.running and self._worker is not None:
            self._worker.cancel()

    def shutdown(self, wait_ms: int = 5000) -> None:
        if not self.running:
            return
        try:
            if self._worker is not None:
                self._worker.cancel()
            self._thread.quit()
            self._thread.wait(wait_ms)
        except Exception:
            logger.exception("Error while shutting down scan thread")

    # ---------- internal slots ----------
    @Slot(int, str)
    def _on_progress(self, value: int, message: str) -> None:
        self._last_progress = value
        self.progress.emit(value, message)

    @Slot(object)
    def _on_finished(self, summary: dict) -> None:
        self.last_summary = summary
        self.scan_finished.emit(summary)

    @Slot(str)
    def _on_failed(self, message: str) -> None:
        logger.error("Scan failed: %s", message)
        self.scan_failed.emit(message)

    @Slot()
    def _on_cancelled(self) -> None:
        self.scan_cancelled.emit()
