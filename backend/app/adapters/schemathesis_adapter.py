"""Schemathesis adapter for property-based API fuzzing.

Runs schemathesis (via CLI) against an OpenAPI/Swagger spec URL and captures
failures (5xx responses, schema violations, server errors) as unified findings.
Degrades gracefully when no spec URL is provided or the binary is absent.
"""

import asyncio
import json
import os
import shutil
from typing import Optional

from app.adapters.base import EngineAdapter
from app.models import ScanType, Severity
from app.schemas import NormalizedFinding


class SchemathesisAdapter(EngineAdapter):
    name = "schemathesis"
    supported_scan_types = (ScanType.DAST,)

    def __init__(
        self,
        *,
        binary: Optional[str] = None,
        overall_timeout: Optional[float] = None,
    ) -> None:
        self.binary = binary or os.getenv("SCHEMATHESIS_PATH", "st")
        self.overall_timeout = float(
            overall_timeout if overall_timeout is not None else os.getenv("SCHEMATHESIS_TIMEOUT", "120")
        )

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    async def run(self, target: str, on_progress=None, **kwargs) -> str:
        spec_url = kwargs.get("spec_url")
        if not spec_url:
            return ""  # No spec -> nothing to fuzz (clean no-op)

        if on_progress:
            await on_progress(10, "api fuzzing with schemathesis")

        cmd = [
            self.binary,
            "run", spec_url,
            "--base-url", target,
            "--checks", "all",
            "--hypothesis-max-examples", "50",
            "--request-timeout", "10000",
            "--dry-run" if False else "--validate-schema=false",
        ]

        # Use internal cassette for JSON output
        cassette_args = ["--cassette-path", "/tmp/st_cassette.yaml"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except (FileNotFoundError, OSError):
            return ""

        out: list[str] = []
        try:
            async with asyncio.timeout(self.overall_timeout):
                assert proc.stdout is not None
                async for line in proc.stdout:
                    out.append(line.decode("utf-8", errors="replace"))
                await proc.wait()
        except (asyncio.TimeoutError, TimeoutError):
            proc.kill()
            try:
                await proc.wait()
            except ProcessLookupError:
                pass

        if on_progress:
            await on_progress(100, "api fuzzing complete")
        return "".join(out)

    def parse(self, raw: str) -> list[NormalizedFinding]:
        if not raw:
            return []
        findings: list[NormalizedFinding] = []

        # Schemathesis text output includes failure blocks like:
        # FAILURES
        # ========
        # POST /api/endpoint
        #   1. Received a response with 5xx status code: 500
        #   ...
        current_endpoint = None
        in_failures = False

        for line in raw.splitlines():
            stripped = line.strip()
            if stripped == "FAILURES" or stripped.startswith("===="):
                in_failures = True
                continue
            if not in_failures:
                continue

            # Endpoint line: "GET /path" or "POST /path"
            if stripped and stripped.split()[0] in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                parts = stripped.split(None, 1)
                if len(parts) == 2:
                    current_endpoint = stripped
                    continue

            # Failure detail line
            if current_endpoint and ("5xx" in stripped or "status code: 5" in stripped
                                     or "server error" in stripped.lower()
                                     or "schema violation" in stripped.lower()
                                     or "response violates" in stripped.lower()):
                findings.append(NormalizedFinding(
                    engine="schemathesis",
                    vuln_type="api-fuzz-failure",
                    severity=Severity.MEDIUM,
                    title=f"API fuzz failure: {current_endpoint}",
                    location=current_endpoint,
                    evidence=stripped[:500],
                    owasp_category="A05:2021-Security Misconfiguration",
                    remediation="Investigate the failing endpoint; ensure proper input validation and error handling.",
                ))

            # Also capture explicit crash/timeout lines
            if "connection refused" in stripped.lower() or "timeout" in stripped.lower():
                if current_endpoint:
                    findings.append(NormalizedFinding(
                        engine="schemathesis",
                        vuln_type="api-fuzz-crash",
                        severity=Severity.HIGH,
                        title=f"API crash/timeout: {current_endpoint}",
                        location=current_endpoint,
                        evidence=stripped[:500],
                        owasp_category="A05:2021-Security Misconfiguration",
                    ))

        return findings
