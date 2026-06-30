"""Secure source-code zip upload for SAST scanning.

Enforces: file size limit, zip-only validation, zip-slip protection during
extraction, and cleanup after the scan finishes.
"""

import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlmodel import Session

from app import orchestrator
from app.database import get_session
from app.models import Scan, ScanStatus, ScanType
from app.schemas import ScanRead

router = APIRouter(prefix="/api", tags=["upload"])

MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE", 50 * 1024 * 1024))  # 50 MB default
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/tmp/ai-pentester-uploads"))


def _safe_extract(zip_path: Path, dest: Path) -> None:
    """Extract a zip file with zip-slip protection."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            # Zip-slip check: ensure extracted path stays within destination.
            member_path = (dest / member.filename).resolve()
            if not str(member_path).startswith(str(dest.resolve())):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Zip-slip attempt detected: {member.filename}",
                )
        zf.extractall(dest)


@router.post("/scans/upload", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def upload_source(
    file: UploadFile = File(...),
    target: str = Form("uploaded-source"),
    scan_type: str = Form("sast"),
    authorized: str = Form("false"),
    session: Session = Depends(get_session),
) -> ScanRead:
    """Upload a source zip for SAST scanning (optionally combined with DAST)."""
    # Consent gate.
    if authorized.lower() != "true":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="authorization is required: set 'authorized' to 'true'",
        )

    # Validate file type.
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .zip files are accepted.",
        )

    # Read and check size.
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size of {MAX_UPLOAD_SIZE // (1024*1024)} MB.",
        )

    # Validate it's actually a zip.
    if not content[:4] == b"PK\x03\x04" and not content[:4] == b"PK\x05\x06":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File does not appear to be a valid zip archive.",
        )

    # Save and extract.
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    extract_dir = Path(tempfile.mkdtemp(dir=UPLOAD_DIR, prefix="src_"))
    zip_path = extract_dir / "upload.zip"
    zip_path.write_bytes(content)

    try:
        _safe_extract(zip_path, extract_dir)
    except HTTPException:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise
    except Exception:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to extract zip archive.",
        )
    finally:
        zip_path.unlink(missing_ok=True)

    # Resolve scan type.
    resolved_type = ScanType.SAST
    if scan_type.lower() == "both":
        resolved_type = ScanType.BOTH
    elif scan_type.lower() == "dast":
        resolved_type = ScanType.DAST

    # Create the scan.
    scan = Scan(
        target=target.strip() or "uploaded-source",
        scan_type=resolved_type,
        source_path=str(extract_dir),
        status=ScanStatus.QUEUED,
        progress=0,
        message="queued",
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    orchestrator.schedule_scan(scan.id)
    return ScanRead.model_validate(scan)
