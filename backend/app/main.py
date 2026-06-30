"""FastAPI application entrypoint for the AI Penetration Tester backend.

Task 1 scope: expose a health check the frontend can poll. The richer data
layer, scan orchestration, and engine adapters arrive in later tasks.
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app import __version__ as APP_VERSION

SERVICE_NAME = "ai-pentester-backend"

DEFAULT_ALLOWED_ORIGINS = "http://localhost:5173,http://localhost:8080"


def get_allowed_origins() -> list[str]:
    """Read CORS origins from the environment.

    Defaults to the local Vite dev server and the docker-compose frontend.
    Configurable via the ``ALLOWED_ORIGINS`` env var (comma-separated) so we
    never need a wildcard origin in a security-focused app.
    """
    raw = os.getenv("ALLOWED_ORIGINS", DEFAULT_ALLOWED_ORIGINS)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


class HealthResponse(BaseModel):
    """Schema returned by the health check endpoint."""

    status: str
    service: str
    version: str


app = FastAPI(
    title="AI Penetration Tester API",
    version=APP_VERSION,
    description=(
        "Backend for the AI Penetration Tester: orchestrates open-source "
        "security scanners and explains findings in plain language."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    """Liveness/readiness probe used by the frontend and container healthcheck."""
    return HealthResponse(status="ok", service=SERVICE_NAME, version=APP_VERSION)


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    """Friendly root pointing at the docs and health endpoints."""
    return {
        "service": SERVICE_NAME,
        "version": APP_VERSION,
        "health": "/health",
        "docs": "/docs",
    }
