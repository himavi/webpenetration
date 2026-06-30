"""SQLModel table models and shared enums for the unified data layer.

IMPORTANT: this module must NOT use ``from __future__ import annotations``.
PEP 563 stringified annotations break SQLModel's ``Relationship()`` resolution
under SQLAlchemy 2.x (the forward reference ``list["Finding"]`` ends up passed
to SQLAlchemy as a literal string it cannot resolve).
"""

import enum
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column
from sqlalchemy import Enum as SAEnum
from sqlmodel import Field, Relationship, SQLModel


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp, used for ``created_at`` defaults."""
    return datetime.now(timezone.utc)


class Severity(str, enum.Enum):
    """Finding severity, ordered from least to most serious."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanType(str, enum.Enum):
    """Black-box dynamic testing (DAST) vs white-box static analysis (SAST)."""

    DAST = "dast"
    SAST = "sast"


class ScanStatus(str, enum.Enum):
    """Lifecycle states for a scan job."""

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class ReportFormat(str, enum.Enum):
    """Supported report export formats."""

    HTML = "html"
    PDF = "pdf"
    JSON = "json"


def _enum_column(enum_cls: type[enum.Enum], **kwargs: object) -> Column:
    """A VARCHAR-backed enum column that stores the lowercase enum *values*.

    Keeps the stored representation ("high") consistent with the JSON API,
    instead of SQLAlchemy's default of persisting member names ("HIGH").
    """
    return Column(
        SAEnum(
            enum_cls,
            native_enum=False,
            values_callable=lambda cls: [member.value for member in cls],
            length=32,
        ),
        **kwargs,
    )


class Scan(SQLModel, table=True):
    """A single scan run against a target (a live URL for DAST or source for SAST)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    target: str = Field(index=True)
    scan_type: ScanType = Field(sa_column=_enum_column(ScanType, nullable=False))
    status: ScanStatus = Field(
        default=ScanStatus.QUEUED,
        sa_column=_enum_column(ScanStatus, nullable=False, index=True),
    )
    progress: int = Field(default=0)
    message: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=utcnow, nullable=False)
    finished_at: Optional[datetime] = Field(default=None)

    findings: list["Finding"] = Relationship(
        back_populates="scan",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    reports: list["Report"] = Relationship(
        back_populates="scan",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )


class Finding(SQLModel, table=True):
    """A normalized security finding produced by an engine adapter.

    The columns mirror :class:`app.schemas.NormalizedFinding`, the single shared
    shape every engine adapter maps into, plus persistence fields (id, scan_id,
    created_at).
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True, nullable=False)

    engine: str = Field(index=True)
    vuln_type: str
    severity: Severity = Field(sa_column=_enum_column(Severity, nullable=False, index=True))
    title: str

    location: Optional[str] = Field(default=None)
    affected_param: Optional[str] = Field(default=None)
    evidence: Optional[str] = Field(default=None)
    cwe_id: Optional[str] = Field(default=None)
    owasp_category: Optional[str] = Field(default=None)
    remediation: Optional[str] = Field(default=None)

    created_at: datetime = Field(default_factory=utcnow, nullable=False)

    scan: Optional[Scan] = Relationship(back_populates="findings")


class Report(SQLModel, table=True):
    """A generated report artifact (HTML/PDF/JSON) for a scan."""

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True, nullable=False)
    format: ReportFormat = Field(sa_column=_enum_column(ReportFormat, nullable=False))
    generated_at: datetime = Field(default_factory=utcnow, nullable=False)
    file_path: Optional[str] = Field(default=None)
    payload: Optional[str] = Field(default=None)

    scan: Optional[Scan] = Relationship(back_populates="reports")
