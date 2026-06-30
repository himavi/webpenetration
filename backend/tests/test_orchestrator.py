"""Tests for the orchestrator stub state machine (queued -> running -> done)."""

import asyncio

from sqlmodel import Session

from app import orchestrator
from app.database import engine
from app.events import broker
from app.models import Scan, ScanStatus, ScanType


def _create_queued_scan() -> int:
    with Session(engine) as session:
        scan = Scan(target="https://example.com", scan_type=ScanType.DAST)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


def test_run_scan_transitions_queued_to_done():
    scan_id = _create_queued_scan()

    async def scenario():
        queue = broker.subscribe(scan_id)
        await orchestrator.run_scan(scan_id, step_delay=0)
        events = []
        while not queue.empty():
            events.append(queue.get_nowait())
        broker.unsubscribe(scan_id, queue)
        return events

    events = asyncio.run(scenario())
    statuses = [event["status"] for event in events]
    progresses = [event["progress"] for event in events]

    assert statuses[0] == "running"
    assert statuses[-1] == "done"
    assert progresses[-1] == 100
    # Progress only ever moves forward.
    assert progresses == sorted(progresses)

    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan.status == ScanStatus.DONE
        assert scan.progress == 100
        assert scan.finished_at is not None


def test_run_scan_missing_scan_is_a_noop():
    # Should not raise even if the scan id does not exist.
    asyncio.run(orchestrator.run_scan(123456, step_delay=0))
