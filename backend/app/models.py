from datetime import datetime, timezone
import enum
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, JSON, Boolean, ForeignKey
from sqlalchemy.orm import relationship

from .database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanProfile(str, enum.Enum):
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(1024), nullable=False)
    label = Column(String(255), default="")
    last_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "label": self.label,
            "last_scan_id": self.last_scan_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    target_url = Column(String(1024), nullable=False)
    profile = Column(String(50), default=ScanProfile.QUICK.value)
    status = Column(String(50), default=ScanStatus.PENDING.value)
    progress = Column(Integer, default=0)
    progress_message = Column(String(255), default="")

    risk_score = Column(Float, nullable=True)
    vulnerabilities_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    warning_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    passed_count = Column(Integer, default=0)
    coverage_percentage = Column(Float, default=0.0)
    duration_seconds = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)
    cookies = Column(JSON, default=list)
    headers = Column(JSON, default=dict)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "target_id": self.target_id,
            "target_url": self.target_url,
            "profile": self.profile,
            "status": self.status,
            "progress": self.progress,
            "progress_message": self.progress_message,
            "risk_score": self.risk_score,
            "vulnerabilities_count": self.vulnerabilities_count or 0,
            "critical_count": self.critical_count or 0,
            "high_count": self.high_count or 0,
            "medium_count": self.medium_count or 0,
            "low_count": self.low_count or 0,
            "warning_count": self.warning_count or 0,
            "info_count": self.info_count or 0,
            "passed_count": self.passed_count or 0,
            "coverage_percentage": self.coverage_percentage or 0.0,
            "duration_seconds": self.duration_seconds or 0.0,
            "error_message": self.error_message,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    module = Column(String(255), nullable=False)
    title = Column(String(255), default="")
    description = Column(Text, default="")
    status = Column(String(50), default="unknown")
    severity = Column(String(50), default="none")
    confidence = Column(Integer, default=0)
    evidence = Column(JSON, default=list)
    impact = Column(JSON, default=dict)
    cvss_score = Column(Float, default=0.0)
    cvss_vector = Column(String(100), default="")
    cwe_id = Column(String(50), default="")
    owasp_category = Column(String(100), default="")
    recommendation = Column(Text, default="")
    occurrences = Column(Integer, default=1)
    affected_url = Column(String(1024), default="")
    verification_status = Column(String(50), default="unverified")
    remediation_steps = Column(JSON, default=list)
    scanner_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="findings")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "module": self.module,
            "title": self.title or self.description or self.module,
            "description": self.description,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence or [],
            "impact": self.impact or {},
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "recommendation": self.recommendation,
            "occurrences": self.occurrences,
            "affected_url": self.affected_url or self.scan.target_url if self.scan else "",
            "verification_status": self.verification_status,
            "remediation_steps": self.remediation_steps or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ScanError(Base):
    __tablename__ = "scan_errors"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    scanner_module = Column(String(255), default="")
    error_message = Column(Text, default="")
    traceback = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    format = Column(String(20), nullable=False)
    file_path = Column(String(1024), nullable=False)
    file_size = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="reports")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "format": self.format,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
