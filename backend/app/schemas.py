from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class ScanCreateRequest(BaseModel):
    target_url: str
    profile: str = "quick"
    label: str = ""
    max_pages: Optional[int] = None
    max_workers: Optional[int] = None


class ScanStatusResponse(BaseModel):
    id: int
    target_url: str
    profile: str
    status: str
    progress: int
    progress_message: str
    risk_score: Optional[float] = None
    vulnerabilities_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    warning_count: int
    info_count: int
    passed_count: int
    coverage_percentage: float
    duration_seconds: float
    error_message: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    module: str
    title: str
    description: str
    status: str
    severity: str
    confidence: int
    evidence: List[Any]
    impact: Dict[str, Any]
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    owasp_category: str
    recommendation: str
    occurrences: int
    affected_url: str
    verification_status: str
    remediation_steps: List[str]
    created_at: Optional[str] = None


class ReportResponse(BaseModel):
    id: int
    scan_id: int
    format: str
    file_path: str
    file_size: int
    created_at: str


class TargetResponse(BaseModel):
    id: int
    url: str
    label: str
    last_scan_id: Optional[int] = None
    created_at: str
    updated_at: str


class ScanResultResponse(BaseModel):
    scan: ScanStatusResponse
    findings: List[FindingResponse]
    reports: List[ReportResponse]


class ScanListItem(BaseModel):
    id: int
    target_url: str
    profile: str
    status: str
    risk_score: Optional[float] = None
    vulnerabilities_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    duration_seconds: float
    created_at: str
