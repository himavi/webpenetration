"""Scan submission, status polling, and live progress over WebSocket."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlmodel import Session

from app import orchestrator
from app.database import get_session
from app.events import broker
from app.models import Scan, ScanStatus
from app.schemas import ScanCreate, ScanRead

router = APIRouter(prefix="/api", tags=["scans"])

_TERMINAL = {ScanStatus.DONE.value, ScanStatus.FAILED.value}


@router.post("/scans", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_scan(payload: ScanCreate, session: Session = Depends(get_session)) -> ScanRead:
    """Create a queued scan (consent already validated) and kick off the runner."""
    scan = Scan(
        target=payload.target,
        scan_type=payload.scan_type,
        status=ScanStatus.QUEUED,
        progress=0,
        message="queued",
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    result = ScanRead.model_validate(scan)

    # Hand off to the async orchestrator stub (queued -> running -> done).
    orchestrator.schedule_scan(scan.id)
    return result


@router.get("/scans/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: int, session: Session = Depends(get_session)) -> Scan:
    """Return the current status and progress of a scan (polling fallback)."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return scan


@router.websocket("/scans/{scan_id}/ws")
async def scan_progress(websocket: WebSocket, scan_id: int) -> None:
    """Stream live progress for a scan until it reaches a terminal state."""
    await websocket.accept()
    # Subscribe before reading the current state so no update slips through the gap.
    queue = broker.subscribe(scan_id)
    try:
        current = await asyncio.to_thread(orchestrator.snapshot, scan_id)
        if current is None:
            await websocket.send_json({"error": "scan not found"})
            return
        await websocket.send_json(current)
        if current["status"] in _TERMINAL:
            return
        while True:
            event = await queue.get()
            await websocket.send_json(event)
            if event.get("status") in _TERMINAL:
                return
    except WebSocketDisconnect:
        pass
    finally:
        broker.unsubscribe(scan_id, queue)
