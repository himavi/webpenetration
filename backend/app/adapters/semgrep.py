"""Semgrep SAST adapter.

Runs Semgrep over uploaded source code with default/auto rules and parses the
JSON output into unified findings (rule id -> vuln_type, severity, file:line ->
location, code snippet -> evidence, CWE/OWASP from metadata).
"""

import asyncio
import json
import os
import shutil
from typing import Optional

from app.adapters.base import EngineAdapter
from app.adapters.owasp import owasp_for_cwe
from app.models import ScanType, Severity
from app.schemas import NormalizedFinding

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepAdapter(EngineAdapter):
    name = "semgrep"
    supported_scan_types = (ScanType.SAST,)

    def __init__(
        self,
        *,
        binary: Optional[str] = None,
        overall_timeout: Optional[float] = None,
    ) -> None:
        self.binary = binary or os.getenv("SEMGREP_PATH", "semgrep")
        self.overall_timeout = float(
            overall_timeout if overall_timeout is not None else os.getenv("SEMGREP_TIMEOUT", "180")
        )

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    async def run(self, target: str, on_progress=None, **kwargs) -> str:
        source_path = kwargs.get("source_path")
        if not source_path or not os.path.isdir(source_path):
            return ""  # No source code uploaded -> clean no-op

        if on_progress:
            await on_progress(10, "running semgrep static analysis")

        cmd = [
            self.binary,
            "scan",
            "--json",
            "--config", "auto",
            "--no-git",
            "--quiet",
            source_path,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
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
            await on_progress(100, "semgrep complete")
        return "".join(out)

    def parse(self, raw: str) -> list[NormalizedFinding]:
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        results = data.get("results") or []
        findings: list[NormalizedFinding] = []
        for result in results:
            finding = self._to_finding(result)
            if finding is not None:
                findings.append(finding)
        return findings

    @staticmethod
    def _to_finding(result: dict) -> Optional[NormalizedFinding]:
        check_id = result.get("check_id") or "semgrep-finding"
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        severity_str = extra.get("severity", "INFO").upper()
        severity = _SEVERITY_MAP.get(severity_str, Severity.INFO)
        message = extra.get("message") or check_id

        # Location: file:start_line-end_line
        path = result.get("path") or ""
        start = result.get("start", {})
        end = result.get("end", {})
        location = path
        if start.get("line"):
            location = f"{path}:{start['line']}"
            if end.get("line") and end["line"] != start["line"]:
                location += f"-{end['line']}"

        # Evidence: the matched code snippet
        evidence = extra.get("lines") or None

        # CWE from metadata
        cwe_ids = metadata.get("cwe") or []
        cwe = None
        if isinstance(cwe_ids, list) and cwe_ids:
            # Format: "CWE-79: ..." or just "CWE-79"
            cwe = str(cwe_ids[0]).split(":")[0].strip()
        elif isinstance(cwe_ids, str):
            cwe = cwe_ids.split(":")[0].strip()

        owasp = owasp_for_cwe(cwe) if cwe else None

        try:
            return NormalizedFinding(
                engine="semgrep",
                vuln_type=str(check_id),
                severity=severity,
                title=message[:200],
                location=location,
                evidence=evidence[:500] if evidence else None,
                cwe_id=cwe,
                owasp_category=owasp,
                remediation=metadata.get("fix") or None,
            )
        except Exception:  # noqa: BLE001
            return None
