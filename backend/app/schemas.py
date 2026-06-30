"""Pydantic schemas: the normalized finding shape plus API read models.

``NormalizedFinding`` is the single shared shape that every engine adapter maps
its output into. The orchestrator attaches it to a scan and persists it as a
:class:`app.models.Finding` row, so the AI explainer and report generator only
ever deal with this one shape regardless of which engine produced the data.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models import ReportFormat, ScanStatus, ScanType, Severity


class NormalizedFinding(BaseModel):
    """Engine-agnostic finding.

    Required fields (engine, vuln_type, severity, title) must be present and
    non-empty; ``severity`` must be a valid :class:`Severity`. Unknown fields are
    rejected so adapter mistakes surface immediately.
    """

    model_config = ConfigDict(extra="forbid")

    engine: str = Field(min_length=1)
    vuln_type: str = Field(min_length=1)
    severity: Severity
    title: str = Field(min_length=1)
    location: Optional[str] = None
    affected_param: Optional[str] = None
    evidence: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None


class FindingRead(BaseModel):
    """A persisted finding as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    engine: str
    vuln_type: str
    severity: Severity
    title: str
    location: Optional[str] = None
    affected_param: Optional[str] = None
    evidence: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    created_at: datetime


class ScanRead(BaseModel):
    """A persisted scan as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    scan_type: ScanType
    status: ScanStatus
    created_at: datetime
    finished_at: Optional[datetime] = None


class ScanWithFindings(ScanRead):
    """A scan plus its related findings."""

    findings: list[FindingRead] = []


class ReportRead(BaseModel):
    """A persisted report artifact as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    format: ReportFormat
    generated_at: datetime
    file_path: Optional[str] = None
    payload: Optional[str] = None


class SeedResponse(BaseModel):
    """Response of the temporary dev seed route."""

    scan: ScanRead
    finding: FindingRead
