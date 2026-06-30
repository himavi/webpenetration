"""Database engine, session dependency, and table creation.

Single-container design: a plain SQLite file accessed through SQLModel. The
location is configurable via ``DATABASE_URL`` (defaults to ``./data/app.db``,
which maps to the mounted ``/app/data`` volume inside the container).
"""

import os
from collections.abc import Iterator
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

# Importing models registers the tables on SQLModel.metadata before create_all.
from app import models  # noqa: F401

DEFAULT_DATABASE_URL = "sqlite:///./data/app.db"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)

# SQLite + a multi-threaded ASGI server needs check_same_thread disabled.
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, echo=False, connect_args=_connect_args)


def _ensure_sqlite_dir(url: str) -> None:
    """Create the parent directory for a file-based SQLite database."""
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        return
    db_path = url[len(prefix):]
    if db_path and db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)


def init_db() -> None:
    """Create database tables if they do not yet exist (idempotent)."""
    _ensure_sqlite_dir(DATABASE_URL)
    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    """FastAPI dependency that yields a database session per request."""
    with Session(engine) as session:
        yield session
