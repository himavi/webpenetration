"""Async job runner: select engine adapters, run them, persist findings.

This is the single-container job runner (plain ``asyncio`` tasks, no
Celery/Redis). For a scan it marks the job running, picks the adapters that
apply to the scan type and are available, runs each against the target,
persists their normalized findings, streams progress to the broker, and finally
marks the scan done.
"""

import asyncio
import os
from datetime import datetime, timezone
from typing import Optional, Sequence

from sqlmodel import Session

from app.adapters import EngineAdapter, get_adapters
from app.database import engine
from app.events import broker
from app.models import Finding, Scan, ScanStatus, ScanType
from app.schemas import NormalizedFinding, ScanRead

DEFAULT_STEP_DELAY = 0.4

# Keep strong references to in-flight tasks so they are not garbage collected.
_tasks: set[asyncio.Task] = set()


def _resolve_step_delay() -> float:
    try:
        return float(os.getenv("SCAN_STEP_DELAY", DEFAULT_STEP_DELAY))
    except ValueError:
        return DEFAULT_STEP_DELAY


def _set_state(
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


def _get_scan_brief(scan_id: int) -> Optional[tuple[str, ScanType]]:
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return None
        return scan.target, scan.scan_type


def _persist_findings(scan_id: int, findings: Sequence[NormalizedFinding]) -> int:
    if not findings:
        return 0
    with Session(engine) as session:
        for finding in findings:
            session.add(Finding(scan_id=scan_id, **finding.model_dump()))
        session.commit()
    return len(findings)


def snapshot(scan_id: int) -> Optional[dict]:
    """Return the current JSON-ready snapshot of a scan, or None if missing."""
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return None
        return ScanRead.model_validate(scan).model_dump(mode="json")


async def _publish(scan_id: int, event: Optional[dict]) -> None:
    if event is not None:
        await broker.publish(scan_id, event)


async def run_scan(
    scan_id: int,
    *,
    adapters: Optional[Sequence[EngineAdapter]] = None,
    step_delay: Optional[float] = None,
) -> None:
    """Run the applicable, available adapters against the scan's target."""
    delay = _resolve_step_delay() if step_delay is None else step_delay
    selected = list(adapters) if adapters is not None else get_adapters()

    try:
        brief = await asyncio.to_thread(_get_scan_brief, scan_id)
        if brief is None:
            return  # scan was deleted before it started
        target, scan_type = brief

        await _publish(
            scan_id,
            await asyncio.to_thread(
                _set_state, scan_id, status=ScanStatus.RUNNING, progress=0, message="starting"
            ),
        )
        await asyncio.sleep(delay)

        usable = await asyncio.to_thread(
            lambda: [a for a in selected if a.supports(scan_type) and a.is_available()]
        )
        if not usable:
            await _publish(
                scan_id,
                await asyncio.to_thread(
                    _set_state,
                    scan_id,
                    status=ScanStatus.DONE,
                    progress=100,
                    message="completed: no engines available",
                    finished=True,
                ),
            )
            return

        total = 0
        count_engines = len(usable)
        for index, adapter in enumerate(usable):
            band_start = max(5, int(index / count_engines * 90))
            band_end = int((index + 1) / count_engines * 90)

            await _publish(
                scan_id,
                await asyncio.to_thread(
                    _set_state, scan_id, progress=band_start, message=f"running {adapter.name}"
                ),
            )

            # Map an adapter's own 0-100 progress into its slice of the overall bar.
            async def on_progress(pct, message, _bs=band_start, _be=band_end, _name=adapter.name):
                mapped = _bs + int(max(0, min(100, pct)) / 100 * (_be - _bs))
                await _publish(
                    scan_id,
                    await asyncio.to_thread(
                        _set_state, scan_id, progress=mapped, message=f"{_name}: {message}"
                    ),
                )

            try:
                raw = await adapter.run(target, on_progress=on_progress)
                findings = adapter.parse(raw)
            except Exception as exc:  # noqa: BLE001 - one engine failing must not abort the scan
                findings = []
                await _publish(
                    scan_id,
                    await asyncio.to_thread(
                        _set_state, scan_id, message=f"{adapter.name} failed: {exc}"
                    ),
                )

            persisted = await asyncio.to_thread(_persist_findings, scan_id, findings)
            total += persisted
            await _publish(
                scan_id,
                await asyncio.to_thread(
                    _set_state,
                    scan_id,
                    progress=band_end,
                    message=f"{adapter.name}: {persisted} findings",
                ),
            )
            await asyncio.sleep(delay)

        await _publish(
            scan_id,
            await asyncio.to_thread(
                _set_state,
                scan_id,
                status=ScanStatus.DONE,
                progress=100,
                message=f"completed: {total} findings",
                finished=True,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - surface unexpected failures as a failed scan
        await _publish(
            scan_id,
            await asyncio.to_thread(
                _set_state, scan_id, status=ScanStatus.FAILED, message=f"scan failed: {exc}", finished=True
            ),
        )


def schedule_scan(scan_id: int, *, step_delay: Optional[float] = None) -> asyncio.Task:
    """Schedule ``run_scan`` on the running event loop and track the task."""
    task = asyncio.create_task(run_scan(scan_id, step_delay=step_delay))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return task
