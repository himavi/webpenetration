"""Shared pytest fixtures.

The orchestrator runs in background tasks and opens its own database sessions,
so request handlers and the orchestrator must share the *same* engine. We point
the real engine at a temporary SQLite file (configured before the app is
imported) and reset the tables before each test for isolation. Scans run with
no step delay so tests stay fast.
"""

import os
import tempfile
from pathlib import Path

# Configure the database + fast scans BEFORE importing the app.
_TMP_DIR = tempfile.mkdtemp(prefix="aipentest-")
os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(_TMP_DIR, "test.db")).replace("\\", "/")
os.environ.setdefault("SCAN_STEP_DELAY", "0")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel  # noqa: E402

from app import database  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_db():
    """Give every test a clean schema on the shared engine."""
    SQLModel.metadata.drop_all(database.engine)
    SQLModel.metadata.create_all(database.engine)
    yield


@pytest.fixture(autouse=True)
def _no_real_engines(monkeypatch):
    """Safety net: route-driven scans must never launch real external engines.

    Tests that exercise the orchestrator pass adapters explicitly to run_scan.
    """
    monkeypatch.setattr("app.orchestrator.get_adapters", lambda: [])


@pytest.fixture(name="session")
def session_fixture():
    with Session(database.engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture():
    with TestClient(app) as client:
        yield client
