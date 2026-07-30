import os
import time
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc

from .config import settings
from .database import engine, Base, get_db
from .models import Target, Scan, ScanStatus, Finding, Report, ScanError
from .schemas import (
    ScanCreateRequest, ScanStatusResponse, FindingResponse,
    ReportResponse, TargetResponse, ScanResultResponse, ScanListItem,
)
from .scan_runner import start_scan_async
from core.ssrf_guard import is_safe_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('SeaScanner.API')

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS.split(","),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

start_time = time.time()


@app.on_event("startup")
def on_startup():
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    os.makedirs(settings.LOGS_DIR, exist_ok=True)
    os.makedirs("data", exist_ok=True)
    Base.metadata.create_all(bind=engine)


@app.get("/")
def root():
    return {"name": settings.APP_NAME, "version": settings.VERSION, "docs": "/api/docs"}


@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_ok = "connected"
    except Exception:
        db_ok = "disconnected"
    return {"status": "healthy", "version": settings.VERSION, "uptime": round(time.time() - start_time, 2), "database": db_ok}


# --- Targets ---

@app.get("/api/targets", response_model=list)
def list_targets(db: Session = Depends(get_db)):
    targets = db.query(Target).order_by(desc(Target.updated_at)).all()
    return [t.to_dict() for t in targets]


@app.post("/api/targets", response_model=dict)
def create_target(url: str = Query(...), label: str = Query(default=""), db: Session = Depends(get_db)):
    if not is_safe_url(url):
        raise HTTPException(status_code=400, detail="SSRF Risk: Internal IP detected")
    target = Target(url=url, label=label)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target.to_dict()


@app.delete("/api/targets/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()
    return {"message": "Deleted"}


# --- Scans ---

@app.get("/api/scans", response_model=list)
def list_scans(page: int = 1, page_size: int = 20, db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(desc(Scan.created_at)).offset((page - 1) * page_size).limit(page_size).all()
    return [s.to_dict() for s in scans]


@app.post("/api/scans", response_model=dict)
def create_scan(req: ScanCreateRequest, db: Session = Depends(get_db)):
    if not is_safe_url(req.target_url):
        raise HTTPException(status_code=400, detail="SSRF Risk: Internal IP detected")
    target_id = None
    target = db.query(Target).filter(Target.url == req.target_url).first()
    if not target and req.label:
        target = Target(url=req.target_url, label=req.label)
        db.add(target)
        db.commit()
        db.refresh(target)
    if target:
        target_id = target.id

    scan = Scan(
        target_id=target_id,
        target_url=req.target_url,
        profile=req.profile,
        status=ScanStatus.PENDING.value,
        cookies=req.cookies or [],
        headers=req.headers or {},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    start_scan_async(scan.id)

    return scan.to_dict()


@app.get("/api/scans/{scan_id}", response_model=dict)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.to_dict()


@app.get("/api/scans/{scan_id}/result", response_model=dict)
def get_scan_result(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.severity).all()
    reports = db.query(Report).filter(Report.scan_id == scan_id).all()
    return {
        "scan": scan.to_dict(),
        "findings": [f.to_dict() for f in findings],
        "reports": [r.to_dict() for r in reports],
    }


# --- Findings ---

@app.get("/api/findings", response_model=list)
def list_findings(scan_id: Optional[int] = None, severity: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Finding)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    findings = q.order_by(
        db.case(
            (Finding.severity == "critical", 0),
            (Finding.severity == "high", 1),
            (Finding.severity == "medium", 2),
            (Finding.severity == "low", 3),
            else_=4
        )
    ).all()
    return [f.to_dict() for f in findings]


@app.get("/api/findings/{finding_id}", response_model=dict)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding.to_dict()


# --- Reports ---

@app.get("/api/reports", response_model=list)
def list_reports(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    q = db.query(Report)
    if scan_id:
        q = q.filter(Report.scan_id == scan_id)
    return [r.to_dict() for r in q.order_by(desc(Report.created_at)).all()]


@app.get("/api/reports/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")
    return FileResponse(report.file_path, filename=os.path.basename(report.file_path))


# --- Stats ---

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total_scans = db.query(Scan).count()
    total_vulns = db.query(db.func.sum(Finding.scan_id)).filter(
        Finding.severity.in_(["critical", "high", "medium", "low"])
    ).scalar() or 0
    
    severity_counts = {}
    for sev in ["critical", "high", "medium", "low"]:
        severity_counts[sev] = db.query(Finding).filter(Finding.severity == sev).count()

    recent_scans = db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED.value).order_by(desc(Scan.created_at)).limit(5).all()

    return {
        "total_scans": total_scans,
        "total_findings": db.query(Finding).count(),
        "vulnerabilities": severity_counts,
        "recent_scans": [s.to_dict() for s in recent_scans],
    }
