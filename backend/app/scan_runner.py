import os
import sys
import time
import traceback
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import Scan, ScanStatus, ScanError, Finding, Report, Target
from .config import settings
from .worker import celery_app

ENGINE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def log_scanner_error(db: Session, scan_id: int, scanner_module: str, exc: Exception, is_critical: bool = False):
    tb_str = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    err = ScanError(
        scan_id=scan_id,
        scanner_module=scanner_module,
        error_message=str(exc)[:2000],
        traceback=tb_str,
    )
    db.add(err)
    db.commit()
    if is_critical:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED.value
            scan.error_message = str(exc)[:1000]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()


@celery_app.task(name="run_scan_task", bind=True, max_retries=1)
def run_scan(self, scan_id: int):
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
        from core.oast_manager import OastManager, INTERACTSH_AVAILABLE

        target = scan.target_url
        cfg = ScanConfig()
        cfg.max_pages = settings.MAX_PAGES
        cfg.max_workers = settings.MAX_WORKERS
        cfg.request_timeout = settings.REQUEST_TIMEOUT
        cfg.use_js_crawler = True
        if scan.cookies:
            cfg.cookies = scan.cookies
        if scan.headers:
            cfg.headers = scan.headers

        session = TrackedSession(config=cfg)
        scan_result = EngineScanResult()
        scan_result.start_time = datetime.now()

        oast_manager = OastManager()
        oast_active = oast_manager.start()

        total_scanners = len(HOST_LEVEL_SCANNERS) + len(PAGE_LEVEL_SCANNERS)
        completed = 0

        def run_scanner(scanner_class, url, is_host):
            nonlocal completed
            try:
                kwargs = {}
                if oast_active and hasattr(scanner_class, '__init__'):
                    import inspect
                    sig = inspect.signature(scanner_class.__init__)
                    if 'oast_manager' in sig.parameters:
                        kwargs['oast_manager'] = oast_manager
                scanner = scanner_class(url, session=session, **kwargs)
                finding = scanner.run()
                scan_result.add_finding(finding)
                if oast_active and finding.is_vulnerable():
                    interactions = oast_manager.get_matching_interactions(scan_id)
                    if interactions:
                        # Phase A9 engine hook: an out-of-band confirmation is
                        # turned into exploited-level evidence. The assessment
                        # pipeline derives verification / confidence / severity
                        # from the evidence — no direct field overrides.
                        from core.evidence import EvidenceBuilder
                        finding.add_evidence(EvidenceBuilder().exploited(
                            "Out-of-band interaction observed on the OAST service "
                            "confirming server-side execution",
                            payload=interactions[0].get('payload_info', {}).get('payload', ''),
                        ))
            except Exception as exc:
                logger.error("Scanner %s failed: %s", scanner_class.__name__, exc)
                log_scanner_error(db, scan_id, scanner_class.__name__, exc, is_critical=False)
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

        if oast_active:
            logger.info("Polling OAST for interactions...")
            oast_manager.poll_all()

        scan_result.end_time = datetime.now()
        scan_result.requests_sent = session.request_count
        scan_result.aggregate_safe_findings()

        # Phase A9: single assessment lifecycle. run_assessment_pipeline() runs
        # per-finding engines (re-assessing any evidence added above), then
        # correlation, Risk, Coverage and the Assessment Engine. The persisted
        # rows below are written from the Assessment's v2-compatible statistics.
        assessment = scan_result.assess()
        stats = assessment.statistics
        logger.info(
            "Assessment complete: risk=%s tier=%s correlations=%s",
            stats.get("risk_score"),
            assessment.overall_tier,
            stats.get("correlations_found"),
        )

        from scanners.verifiers.base_verifier import SQLiVerifier, XSSVerifier
        for verifier_cls in [SQLiVerifier, XSSVerifier]:
            try:
                verifier = verifier_cls(session=session)
                verifier.verify_all(scan_result.findings, target)
            except Exception as exc:
                logger.error("Verifier %s failed: %s", verifier_cls.__name__, exc)

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

    except Exception as exc:
        log_scanner_error(db, scan_id, "ScanRunner", exc, is_critical=True)
    finally:
        db.close()


def generate_reports(db: Session, scan_id: int, target: str, scan_result):
    from core.reporter import Reporter
    from core.pdf_reporter import PDFReporter

    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    branding = {
        'company_name': 'SEA Corporate',
        'consultant_name': '',
        'client_name': '',
        'report_id': f"SR-{scan_id}",
        'logo_url': '',
    }

    reporter = Reporter(branding=branding)

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
        except Exception as exc:
            logger.error("Report generation failed for %s: %s", fmt, exc)
            log_scanner_error(db, scan_id, f"ReportGenerator.{fmt}", exc)

    try:
        pdf_reporter = PDFReporter(branding=branding)
        pdf_path = pdf_reporter.generate_pdf(scan_result, target)
        if pdf_path and os.path.exists(pdf_path):
            report = Report(
                scan_id=scan_id,
                format="pdf",
                file_path=os.path.abspath(pdf_path),
                file_size=os.path.getsize(pdf_path),
            )
            db.add(report)
    except Exception as exc:
        logger.error("PDF report generation failed: %s", exc)
        log_scanner_error(db, scan_id, "ReportGenerator.pdf", exc)

    db.commit()

    if scan and scan.target_id:
        target_obj = db.query(Target).filter(Target.id == scan.target_id).first()
        if target_obj:
            target_obj.last_scan_id = scan.id
            target_obj.updated_at = datetime.now(timezone.utc)
            db.commit()


def start_scan_async(scan_id: int):
    task = run_scan.delay(scan_id)
    logger.info("Scan %d dispatched to Celery worker (task %s)", scan_id, task.id)
    return task


import logging
logger = logging.getLogger('SeaScanner.API')
