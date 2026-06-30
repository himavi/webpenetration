"""Report generation and download endpoints (HTML / PDF / JSON)."""

import json

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from sqlmodel import Session, select

from app import reports
from app.database import get_session
from app.models import Finding, Report, ReportFormat, Scan
from app.schemas import ReportRead

router = APIRouter(prefix="/api", tags=["reports"])


def _load_scan_and_findings(scan_id: int, session: Session) -> tuple[Scan, list[Finding]]:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    findings = list(session.exec(select(Finding).where(Finding.scan_id == scan_id)).all())
    return scan, findings


def _persist_report(session: Session, scan_id: int, fmt: ReportFormat, payload: str | None) -> None:
    session.add(Report(scan_id=scan_id, format=fmt, payload=payload))
    session.commit()


@router.get("/scans/{scan_id}/report.json")
def report_json(scan_id: int, session: Session = Depends(get_session)) -> Response:
    scan, findings = _load_scan_and_findings(scan_id, session)
    data = reports.build_report_data(scan, findings)
    body = json.dumps(data, indent=2)
    _persist_report(session, scan_id, ReportFormat.JSON, body)
    return JSONResponse(content=data)


@router.get("/scans/{scan_id}/report.html", response_class=HTMLResponse)
def report_html(scan_id: int, session: Session = Depends(get_session)) -> HTMLResponse:
    scan, findings = _load_scan_and_findings(scan_id, session)
    data = reports.build_report_data(scan, findings)
    html = reports.render_html(data)
    _persist_report(session, scan_id, ReportFormat.HTML, html)
    return HTMLResponse(content=html)


@router.get("/scans/{scan_id}/report.pdf")
def report_pdf(scan_id: int, session: Session = Depends(get_session)) -> Response:
    if not reports.pdf_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PDF generation is unavailable (WeasyPrint not installed in this environment).",
        )
    scan, findings = _load_scan_and_findings(scan_id, session)
    data = reports.build_report_data(scan, findings)
    html = reports.render_html(data)
    pdf_bytes = reports.render_pdf(html)
    _persist_report(session, scan_id, ReportFormat.PDF, None)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-report.pdf"'},
    )


@router.get("/scans/{scan_id}/reports", response_model=list[ReportRead])
def list_reports(scan_id: int, session: Session = Depends(get_session)) -> list[Report]:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return list(session.exec(select(Report).where(Report.scan_id == scan_id)).all())
