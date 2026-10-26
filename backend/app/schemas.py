from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Severity = Literal["critical", "high", "medium", "low", "informational"]


class ScanRequest(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=2048)

    @field_validator("target_url")
    @classmethod
    def clean_target(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Enter a website URL to scan.")
        return value


class Finding(BaseModel):
    id: str
    severity: Severity
    title: str
    category: str
    evidence: str
    description: str
    why_it_matters: str
    risk: str
    recommendation: str
    score_impact: int = 0


class HeaderCheck(BaseModel):
    name: str
    present: bool
    value: str | None = None
    note: str
    severity: Severity = "informational"


class CookieCheck(BaseModel):
    name: str
    secure: bool | None = None
    http_only: bool | None = None
    same_site: str | None = None
    raw: str
    note: str


class TlsStatus(BaseModel):
    requested_https: bool
    available: bool | None
    valid_certificate: bool | None
    expires_at: str | None = None
    protocol: str | None = None
    error: str | None = None


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class ScanReport(BaseModel):
    scan_id: str
    target_url: str
    normalized_url: str
    hostname: str
    scanned_at: datetime
    completed_at: datetime
    reachable: bool
    status_code: int | None = None
    final_url: str | None = None
    response_time_ms: int | None = None
    request_count: int = 0
    checks_completed: int = 0
    evidence_sufficient: bool = False
    score: int | None = None
    score_label: str
    score_note: str
    summary: ScanSummary
    tls: TlsStatus
    headers: list[HeaderCheck] = []
    cookies: list[CookieCheck] = []
    public_signals: list[str] = []
    findings: list[Finding] = []
    errors: list[str] = []
    limitations: list[str] = []


class ScanListItem(BaseModel):
    scan_id: str
    target_url: str
    hostname: str
    scanned_at: datetime
    score: int | None
    score_label: str
    finding_count: int
