"""Async job-runner stub that drives a scan through queued -> running -> done.

There are no real engines yet (those arrive from Task 4). This simulates a
sequence of progress steps, persists status/progress to the database, and
publishes each snapshot to the progress broker so WebSocket clients see updates
live. It uses plain ``asyncio`` tasks - the single-container job runner - rather
than Celery/Redis.
"""

import asyncio
import os
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Session

from app.database import engine
from app.events import broker
from app.models import Scan, ScanStatus
from app.schemas import ScanRead

DEFAULT_STEP_DELAY = 0.6

# (progress, message) milestones the stub walks through while "scanning".
STEPS: list[tuple[int, str]] = [
    (10, "initializing scan engines"),
    (30, "spidering target"),
    (55, "passive analysis"),
    (80, "active vulnerability checks"),
    (95, "correlating and normalizing findings"),
]

# Keep strong references to in-flight tasks so they are not garbage collected.
_tasks: set[asyncio.Task] = set()


def _resolve_step_delay() -> float:
    try:
        return float(os.getenv("SCAN_STEP_DELAY", DEFAULT_STEP_DELAY))
    except ValueError:
        return DEFAULT_STEP_DELAY


def _apply(
    scan_id: int,
    *,
    status: Optional[ScanStatus] = None,
    progress: Optional[int] = None,
    message: Optional[str] = None,
    finished: bool = False,
) -> Optional[dict]:
    """Persist a state change for a scan and return a JSON-ready snapshot."""
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return None
        if status is not None:
            scan.status = status
        if progress is not None:
            scan.progress = progress
        if message is not None:
            scan.message = message
        if finished:
            scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return ScanRead.model_validate(scan).model_dump(mode="json")


def snapshot(scan_id: int) -> Optional[dict]:
    """Return the current JSON-ready snapshot of a scan, or None if missing."""
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return None
        return ScanRead.model_validate(scan).model_dump(mode="json")


async def run_scan(scan_id: int, *, step_delay: Optional[float] = None) -> None:
    """Walk a scan through its simulated lifecycle, persisting and publishing."""
    delay = _resolve_step_delay() if step_delay is None else step_delay
    try:
        event = await asyncio.to_thread(
            _apply, scan_id, status=ScanStatus.RUNNING, progress=0, message="starting"
        )
        if event is None:
            return  # scan was deleted before it started
        await broker.publish(scan_id, event)

        for progress, message in STEPS:
            await asyncio.sleep(delay)
            event = await asyncio.to_thread(_apply, scan_id, progress=progress, message=message)
            if event is not None:
                await broker.publish(scan_id, event)

        await asyncio.sleep(delay)
        event = await asyncio.to_thread(
            _apply,
            scan_id,
            status=ScanStatus.DONE,
            progress=100,
            message="scan complete",
            finished=True,
        )
        if event is not None:
            await broker.publish(scan_id, event)
    except Exception as exc:  # noqa: BLE001 - stub: surface any failure as a failed scan
        event = await asyncio.to_thread(
            _apply,
            scan_id,
            status=ScanStatus.FAILED,
            message=f"scan failed: {exc}",
            finished=True,
        )
        if event is not None:
            await broker.publish(scan_id, event)


def schedule_scan(scan_id: int, *, step_delay: Optional[float] = None) -> asyncio.Task:
    """Schedule ``run_scan`` on the running event loop and track the task."""
    task = asyncio.create_task(run_scan(scan_id, step_delay=step_delay))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return task
