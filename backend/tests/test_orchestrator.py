"""Tests for the adapter-running orchestrator (runs engines, persists findings)."""

import asyncio
import json

from sqlmodel import Session, select

from app import orchestrator
from app.adapters.base import EngineAdapter
from app.adapters.nuclei import NucleiAdapter
from app.database import engine
from app.models import Finding, Scan, ScanStatus, ScanType, Severity
from app.schemas import NormalizedFinding


class FakeAdapter(EngineAdapter):
    def __init__(self, name, findings, available=True):
        self.name = name
        self._findings = findings
        self._available = available

    def is_available(self):
        return self._available

    async def run(self, target):
        return "raw-output"

    def parse(self, raw):
        return list(self._findings)


def _queued_scan(scan_type=ScanType.DAST) -> int:
    with Session(engine) as session:
        scan = Scan(target="https://example.com", scan_type=scan_type)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


def _findings_for(scan_id):
    with Session(engine) as session:
        return list(session.exec(select(Finding).where(Finding.scan_id == scan_id)).all())


def test_orchestrator_runs_adapter_persists_findings_and_completes():
    scan_id = _queued_scan()
    adapter = FakeAdapter(
        "fake",
        [
            NormalizedFinding(engine="fake", vuln_type="xss", severity=Severity.HIGH, title="XSS"),
            NormalizedFinding(
                engine="fake", vuln_type="open-redirect", severity=Severity.LOW, title="Redirect"
            ),
        ],
    )

    asyncio.run(orchestrator.run_scan(scan_id, adapters=[adapter], step_delay=0))

    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan.status == ScanStatus.DONE
        assert scan.progress == 100
        assert scan.finished_at is not None

    rows = _findings_for(scan_id)
    assert len(rows) == 2
    assert {row.vuln_type for row in rows} == {"xss", "open-redirect"}
    assert all(row.engine == "fake" for row in rows)


def test_orchestrator_skips_unavailable_adapters():
    scan_id = _queued_scan()
    adapter = FakeAdapter(
        "fake",
        [NormalizedFinding(engine="fake", vuln_type="x", severity=Severity.INFO, title="x")],
        available=False,
    )

    asyncio.run(orchestrator.run_scan(scan_id, adapters=[adapter], step_delay=0))

    with Session(engine) as session:
        assert session.get(Scan, scan_id).status == ScanStatus.DONE
    assert _findings_for(scan_id) == []


def test_orchestrator_runs_nuclei_with_subprocess_stubbed(monkeypatch):
    sample = json.dumps(
        {
            "template-id": "tech-detect",
            "info": {"name": "Technology Detection", "severity": "info"},
            "matched-at": "https://example.com",
        }
    )
    adapter = NucleiAdapter()

    async def fake_run(target):
        return sample

    monkeypatch.setattr(adapter, "run", fake_run)
    monkeypatch.setattr(adapter, "is_available", lambda: True)

    scan_id = _queued_scan()
    asyncio.run(orchestrator.run_scan(scan_id, adapters=[adapter], step_delay=0))

    rows = _findings_for(scan_id)
    assert len(rows) == 1
    assert rows[0].engine == "nuclei"
    assert rows[0].vuln_type == "tech-detect"


def test_orchestrator_handles_adapter_error_gracefully():
    class BoomAdapter(EngineAdapter):
        name = "boom"

        def is_available(self):
            return True

        async def run(self, target):
            raise RuntimeError("boom")

        def parse(self, raw):
            return []

    scan_id = _queued_scan()
    asyncio.run(orchestrator.run_scan(scan_id, adapters=[BoomAdapter()], step_delay=0))

    with Session(engine) as session:
        # A failing engine degrades gracefully: the scan still completes.
        assert session.get(Scan, scan_id).status == ScanStatus.DONE
    assert _findings_for(scan_id) == []


def test_run_scan_missing_scan_is_a_noop():
    asyncio.run(orchestrator.run_scan(123456, adapters=[], step_delay=0))
