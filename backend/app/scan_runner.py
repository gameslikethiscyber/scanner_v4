import os
import sys
import time
import threading
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import Scan, ScanStatus, Finding, Report, Target
from .config import settings

ENGINE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def run_scan(scan_id: int, on_progress: Optional[callable] = None):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        sys.path.insert(0, ENGINE_DIR)

        from core.config import ScanConfig
        from core.finding import ScanResult as EngineScanResult
        from core.http_client import TrackedSession
        from scanners.registry import HOST_LEVEL_SCANNERS, PAGE_LEVEL_SCANNERS
        from core.correlation_engine import CorrelationEngine

        target = scan.target_url
        cfg = ScanConfig()
        cfg.max_pages = settings.MAX_PAGES
        cfg.max_workers = settings.MAX_WORKERS
        cfg.request_timeout = settings.REQUEST_TIMEOUT

        session = TrackedSession()
        scan_result = EngineScanResult()
        scan_result.start_time = datetime.now()

        total_scanners = len(HOST_LEVEL_SCANNERS) + len(PAGE_LEVEL_SCANNERS)
        completed = 0

        def run_scanner(scanner_class, url, is_host):
            nonlocal completed
            try:
                if is_host:
                    scanner = scanner_class(url, session=session)
                else:
                    scanner = scanner_class(url, session=session)
                finding = scanner.run()
                scan_result.add_finding(finding)
            except Exception:
                pass
            finally:
                completed += 1
                progress = int((completed / total_scanners) * 100)
                scan.progress = progress
                scan.progress_message = f"Running {scanner_class.__name__}..."
                db.commit()

        for sc in HOST_LEVEL_SCANNERS:
            run_scanner(sc, target, True)

        for sc in PAGE_LEVEL_SCANNERS:
            run_scanner(sc, target, False)

        scan_result.end_time = datetime.now()
        scan_result.requests_sent = session.request_count
        scan_result.aggregate_safe_findings()

        correlation_engine = CorrelationEngine()
        correlation_results = correlation_engine.correlate(scan_result.findings)
        scan_result.correlation_results = correlation_engine.get_correlation_summary()
        logger.info(f"Correlation: {len(correlation_results)} correlations found")

        stats = scan_result.get_statistics()

        scan.status = ScanStatus.COMPLETED.value
        scan.completed_at = datetime.now(timezone.utc)
        scan.progress = 100
        scan.progress_message = "Scan completed"
        scan.risk_score = stats.get("risk_score", 0)
        scan.vulnerabilities_count = stats.get("vulnerabilities", 0)
        scan.critical_count = stats.get("critical", 0)
        scan.high_count = stats.get("high", 0)
        scan.medium_count = stats.get("medium", 0)
        scan.low_count = stats.get("low", 0)
        scan.warning_count = stats.get("warning", 0)
        scan.info_count = stats.get("info", 0)
        scan.passed_count = stats.get("safe", 0)
        scan.coverage_percentage = stats.get("coverage_percentage", 0)
        scan.duration_seconds = stats.get("duration", 0)
        db.commit()

        for ef in scan_result.findings:
            finding = Finding(
                scan_id=scan.id,
                module=ef.module or "",
                title=ef.title or ef.description or ef.reason or ef.module or "",
                description=ef.description or ef.reason or "",
                status=ef.status.value if hasattr(ef.status, 'value') else str(ef.status),
                severity=ef.severity.value if hasattr(ef.severity, 'value') else str(ef.severity),
                confidence=ef.confidence,
                evidence=[e.to_dict() if hasattr(e, 'to_dict') else str(e) for e in ef.evidence],
                impact=ef.impact,
                cvss_score=ef.cvss_score,
                cvss_vector=ef.cvss_vector,
                cwe_id=ef.cwe_id,
                owasp_category=ef.owasp_category,
                recommendation=ef.recommendation,
                occurrences=ef.occurrences,
                affected_url=ef.target or target,
                verification_status=ef.verification_status,
                remediation_steps=ef.remediation_steps,
                scanner_data=ef.to_dict() if hasattr(ef, 'to_dict') else {},
            )
            db.add(finding)
        db.commit()

        generate_reports(db, scan.id, target, scan_result)

    except Exception as e:
        import logging
        logging.getLogger(__name__).exception("Scan failed")
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED.value
            scan.error_message = str(e)[:1000]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


def generate_reports(db: Session, scan_id: int, target: str, scan_result):
    from core.reporter import Reporter

    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    reporter = Reporter()

    for fmt, method in [
        ("html", reporter.generate_html),
        ("json", reporter.generate_json),
        ("md", reporter.generate_markdown),
        ("csv", reporter.generate_csv),
        ("txt", reporter.generate_txt),
    ]:
        try:
            path = method(scan_result, target)
            if path and os.path.exists(path):
                report = Report(
                    scan_id=scan_id,
                    format=fmt,
                    file_path=os.path.abspath(path),
                    file_size=os.path.getsize(path),
                )
                db.add(report)
        except Exception:
            pass

    db.commit()

    if scan and scan.target_id:
        target_obj = db.query(Target).filter(Target.id == scan.target_id).first()
        if target_obj:
            target_obj.last_scan_id = scan.id
            target_obj.updated_at = datetime.now(timezone.utc)
            db.commit()


def start_scan_async(scan_id: int):
    thread = threading.Thread(target=run_scan, args=(scan_id,), daemon=True)
    thread.start()
    return thread


import logging
logger = logging.getLogger('SeaScanner.API')
