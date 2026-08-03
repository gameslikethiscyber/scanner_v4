"""
Calibration feature flags + instrumentation (P4.2).

Phase 4.2 requirement: instrument the engine to observe *current* behavior
without changing anything visible. All diagnostics are gated behind an env flag
so default runs are byte-identical to v4.9.0.

Flag contract:
    SEA_CALIBRATION
      unset / "0" / "off"  -> behaviour-neutral (default; the only stable mode)
      "report"             -> write calibration diagnostics to report_dir only
      "v2"                 -> reserved (future normalization compared against frozen v4.2)

SCOPE: nothing here may alter finding result, confidence, risk, severity, report,
or assessment. When the flag is OFF this module is inert.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger('SeaScanner.CalibrationFlags')

_ENV = "SEA_CALIBRATION"


def state() -> str:
    return (os.environ.get(_ENV, "off") or "off").strip().lower()


def enabled() -> bool:
    return state() not in ("off", "", "0")


def write_dir() -> str:
    return os.environ.get("SEA_CALIBRATION_DIR", "").strip() or "reports/calibration"


class CalibrationCollector:
    """Accumulates per-finding and scan-level observations (OBSERVATION only)."""

    def __init__(self) -> None:
        self.entries: List[Dict[str, Any]] = []
        self.scan: Dict[str, Any] = {}
        self._closed = False

    def record_finding(self, f: Any) -> None:
        """Record a No-op; called by the pipeline when enabled."""
        self.entries.append({
            "module": getattr(f, "module", ""),
            "status": (getattr(getattr(f, "status", None), "value", None)),
            "confidence": getattr(f, "confidence", 0),
            "evidence_quality": getattr(f, "evidence_quality", 0),
            "verification_status": getattr(f, "verification_status", ""),
            "severity": (getattr(getattr(f, "severity", None), "value", None)),
            "evidence_count": len(getattr(f, "evidence", []) or []),
            "fingerprint_confidence": _extract(f.fingerprint),
        })

    def record_scan(self, scan_result: Any) -> None:
        if self._closed:
            return
        self._closed = True
        stats = getattr(scan_result, "get_statistics", lambda: {})() or {}
        self.scan = {
            "risk_score": stats.get("risk_score"),
            "highest_severity": stats.get("highest_severity"),
            "overall_tier": stats.get("overall_tier"),
            "vulnerabilities": len(getattr(scan_result, "get_vulnerabilities", list)()),
        }

    def save(self, directory: Optional[str] = None) -> Optional[str]:
        if state() == "off":
            return None
        out_dir = directory or write_dir()
        import os
        os.makedirs(out_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(out_dir, f"calibration_diagnostics_{stamp}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"scheme": "v4.2-frozen", "entries": self.entries,
                       "scan": self.scan}, fh, indent=2, default=str)
        logger.info("Wrote calibration diagnostics: %s", path)
        return path


def _extract(fingerprint: Dict[str, Any]) -> Dict[str, Any]:
    if not fingerprint:
        return {}
    out = {}
    for k, v in fingerprint.items():
        if k.endswith("_confidence"):
            out[k] = v
    return out


# Module-level collector, lazily used by the pipeline when the flag is on.
_COLLECTOR: Optional[CalibrationCollector] = None


def collector() -> CalibrationCollector:
    global _COLLECTOR
    if _COLLECTOR is None:
        _COLLECTOR = CalibrationCollector()
    return _COLLECTOR