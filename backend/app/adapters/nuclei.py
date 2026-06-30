"""Nuclei engine adapter.

Nuclei (ProjectDiscovery) is a fast, template-based scanner. We run it with
JSON-Lines output, time-box the subprocess, and map each result line into the
unified ``NormalizedFinding`` shape.
"""

import asyncio
import json
import os
import shutil
from typing import Optional

from app.adapters.base import EngineAdapter
from app.models import ScanType, Severity
from app.schemas import NormalizedFinding

_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _map_severity(value: Optional[str]) -> Severity:
    # nuclei also emits "unknown"; anything unrecognized degrades to info.
    return _SEVERITY_MAP.get((value or "").strip().lower(), Severity.INFO)


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value or None


class NucleiAdapter(EngineAdapter):
    name = "nuclei"
    supported_scan_types = (ScanType.DAST,)

    def __init__(
        self,
        *,
        binary: Optional[str] = None,
        overall_timeout: Optional[float] = None,
        request_timeout: Optional[int] = None,
        tags: Optional[str] = None,
        severity: Optional[str] = None,
        rate_limit: Optional[str] = None,
        extra_args: Optional[str] = None,
    ) -> None:
        self.binary = binary or os.getenv("NUCLEI_PATH", "nuclei")
        self.overall_timeout = float(
            overall_timeout if overall_timeout is not None else os.getenv("NUCLEI_TIMEOUT", "120")
        )
        self.request_timeout = int(
            request_timeout if request_timeout is not None else os.getenv("NUCLEI_REQUEST_TIMEOUT", "5")
        )
        self.tags = tags if tags is not None else os.getenv("NUCLEI_TAGS", "")
        self.severity = severity if severity is not None else os.getenv("NUCLEI_SEVERITY", "")
        self.rate_limit = rate_limit if rate_limit is not None else os.getenv("NUCLEI_RATE_LIMIT", "")
        self.extra_args = extra_args if extra_args is not None else os.getenv("NUCLEI_EXTRA_ARGS", "")

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def _build_command(self) -> list[str]:
        # The target is fed via stdin (nuclei's -u/-target flag path is unreliable
        # in v3.9 input handling), so it is not part of the argument list here.
        cmd = [
            self.binary,
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-no-interactsh",
            "-timeout", str(self.request_timeout),
        ]
        if self.tags:
            cmd += ["-tags", self.tags]
        if self.severity:
            cmd += ["-severity", self.severity]
        if self.rate_limit:
            cmd += ["-rate-limit", str(self.rate_limit)]
        if self.extra_args:
            cmd += self.extra_args.split()
        return cmd

    async def run(self, target: str, on_progress=None) -> str:
        """Run nuclei (target via stdin), returning JSONL stdout (partial on timeout)."""
        cmd = self._build_command()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except (FileNotFoundError, OSError):
            return ""

        # Feed the target on stdin (the canonical, reliable nuclei input path).
        if proc.stdin is not None:
            try:
                proc.stdin.write(f"{target}\n".encode())
                await proc.stdin.drain()
                proc.stdin.close()
            except (BrokenPipeError, ConnectionResetError):
                pass

        lines: list[str] = []
        try:
            async with asyncio.timeout(self.overall_timeout):
                assert proc.stdout is not None
                async for raw_line in proc.stdout:
                    lines.append(raw_line.decode("utf-8", errors="replace"))
                await proc.wait()
        except (asyncio.TimeoutError, TimeoutError):
            # Time-box hit: stop nuclei and keep whatever it produced so far.
            proc.kill()
            try:
                await proc.wait()
            except ProcessLookupError:
                pass
        return "".join(lines)

    def parse(self, raw: str) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            finding = self._to_finding(data)
            if finding is not None:
                findings.append(finding)
        return findings

    @staticmethod
    def _to_finding(data: dict) -> Optional[NormalizedFinding]:
        info = data.get("info") or {}
        classification = info.get("classification") or {}

        template_id = data.get("template-id") or data.get("templateID") or "nuclei-finding"
        title = info.get("name") or template_id
        location = data.get("matched-at") or data.get("matched_at") or data.get("host")

        matcher = data.get("matcher-name")
        extracted = data.get("extracted-results") or []
        evidence_parts = []
        if matcher:
            evidence_parts.append(f"matcher: {matcher}")
        if extracted:
            evidence_parts.append("extracted: " + ", ".join(str(item) for item in extracted))
        evidence = "; ".join(evidence_parts) or None

        try:
            return NormalizedFinding(
                engine="nuclei",
                vuln_type=str(template_id),
                severity=_map_severity(info.get("severity")),
                title=str(title),
                location=location,
                evidence=evidence,
                cwe_id=_first(classification.get("cwe-id")),
                remediation=info.get("remediation"),
            )
        except Exception:  # noqa: BLE001 - never let one bad line abort the parse
            return None
