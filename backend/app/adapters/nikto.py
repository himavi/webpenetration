"""Nikto engine adapter.

Runs Nikto (web server scanner) as a time-boxed subprocess with JSON output and
parses its results into unified findings for server/config issues.
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

_OSVDB_SEVERITY = {
    # Nikto doesn't emit severity levels natively; we assign based on message hints.
    # Default is LOW for most informational server-config issues.
}


def _guess_severity(msg: str) -> Severity:
    low = msg.lower()
    if any(w in low for w in ("remote code", "backdoor", "rce", "arbitrary")):
        return Severity.CRITICAL
    if any(w in low for w in ("injection", "xss", "traversal", "sql")):
        return Severity.HIGH
    if any(w in low for w in ("directory listing", "default", "sensitive", "disclosure")):
        return Severity.MEDIUM
    return Severity.LOW


class NiktoAdapter(EngineAdapter):
    name = "nikto"
    supported_scan_types = (ScanType.DAST,)

    def __init__(
        self,
        *,
        binary: Optional[str] = None,
        overall_timeout: Optional[float] = None,
    ) -> None:
        self.binary = binary or os.getenv("NIKTO_PATH", "nikto")
        self.overall_timeout = float(
            overall_timeout if overall_timeout is not None else os.getenv("NIKTO_TIMEOUT", "120")
        )

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    async def run(self, target: str, on_progress=None) -> str:
        if on_progress:
            await on_progress(5, "nikto scanning")

        cmd = [
            self.binary,
            "-h", target,
            "-Format", "json",
            "-o", "/dev/stdout",
            "-nointeractive",
            "-maxtime", str(int(self.overall_timeout)),
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
            async with asyncio.timeout(self.overall_timeout + 30):
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
            await on_progress(100, "nikto complete")
        return "".join(out)

    def parse(self, raw: str) -> list[NormalizedFinding]:
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        # Nikto JSON wraps results under various structures depending on version.
        vulns = []
        if isinstance(data, dict):
            # Often: {"host": ..., "vulnerabilities": [...]}
            vulns = data.get("vulnerabilities") or []
            # Or nested inside a host key.
            if not vulns:
                for v in data.values():
                    if isinstance(v, dict) and "vulnerabilities" in v:
                        vulns = v["vulnerabilities"]
                        break
        elif isinstance(data, list):
            vulns = data

        findings: list[NormalizedFinding] = []
        for item in vulns:
            finding = self._to_finding(item)
            if finding is not None:
                findings.append(finding)
        return findings

    @staticmethod
    def _to_finding(item: dict) -> Optional[NormalizedFinding]:
        msg = item.get("msg") or item.get("message") or ""
        url = item.get("url") or item.get("uri") or None
        method = item.get("method")
        osvdb = item.get("OSVDB") or item.get("id") or ""

        location = url
        if method and url:
            location = f"{method} {url}"

        title = msg[:120] if msg else f"OSVDB-{osvdb}"
        severity = _guess_severity(msg)

        try:
            return NormalizedFinding(
                engine="nikto",
                vuln_type=f"nikto-{osvdb}" if osvdb else "nikto-finding",
                severity=severity,
                title=title,
                location=location,
                evidence=msg if len(msg) > 120 else None,
                cwe_id=None,
                owasp_category="A05:2021-Security Misconfiguration",
            )
        except Exception:  # noqa: BLE001
            return None
