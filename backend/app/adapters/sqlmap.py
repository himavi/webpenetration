"""sqlmap engine adapter.

Runs sqlmap as a controlled, time-boxed subprocess (non-interactive ``--batch``,
capped crawl/level/risk, hard overall timeout) and parses its injection report
from stdout into unified findings: affected parameter, injection technique(s),
payload, and back-end DBMS.
"""

import asyncio
import os
import re
import shutil
from typing import Optional

from app.adapters.base import EngineAdapter
from app.adapters.owasp import owasp_for_cwe
from app.models import ScanType, Severity
from app.schemas import NormalizedFinding

_PARAM_RE = re.compile(r"Parameter:\s*(.+?)\s*\(([^)]+)\)")
_TYPE_RE = re.compile(r"Type:\s*(.+)")
_TITLE_RE = re.compile(r"Title:\s*(.+)")
_PAYLOAD_RE = re.compile(r"Payload:\s*(.+)")
_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)")


class SqlmapAdapter(EngineAdapter):
    name = "sqlmap"
    supported_scan_types = (ScanType.DAST,)

    def __init__(
        self,
        *,
        binary: Optional[str] = None,
        overall_timeout: Optional[float] = None,
        request_timeout: Optional[int] = None,
        level: Optional[int] = None,
        risk: Optional[int] = None,
        crawl: Optional[int] = None,
        extra_args: Optional[str] = None,
    ) -> None:
        self.binary = binary or os.getenv("SQLMAP_PATH", "sqlmap")
        self.overall_timeout = float(
            overall_timeout if overall_timeout is not None else os.getenv("SQLMAP_TIMEOUT", "180")
        )
        self.request_timeout = int(
            request_timeout if request_timeout is not None else os.getenv("SQLMAP_REQUEST_TIMEOUT", "10")
        )
        self.level = int(level if level is not None else os.getenv("SQLMAP_LEVEL", "1"))
        self.risk = int(risk if risk is not None else os.getenv("SQLMAP_RISK", "1"))
        self.crawl = int(crawl if crawl is not None else os.getenv("SQLMAP_CRAWL", "1"))
        self.extra_args = extra_args if extra_args is not None else os.getenv("SQLMAP_EXTRA_ARGS", "")
        self._last_target: Optional[str] = None

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def _build_command(self, target: str) -> list[str]:
        cmd = [
            self.binary,
            "-u", target,
            "--batch",
            "--disable-coloring",
            "--level", str(self.level),
            "--risk", str(self.risk),
            "--random-agent",
            "--threads", "2",
            "--timeout", str(self.request_timeout),
            "--retries", "1",
            "--flush-session",
        ]
        if self.crawl > 0:
            cmd += ["--crawl", str(self.crawl), "--forms"]
        if self.extra_args:
            cmd += self.extra_args.split()
        return cmd

    async def run(self, target: str, on_progress=None) -> str:
        self._last_target = target
        if on_progress is not None:
            await on_progress(5, "probing for sql injection")

        cmd = self._build_command(target)
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
                async for raw_line in proc.stdout:
                    out.append(raw_line.decode("utf-8", errors="replace"))
                await proc.wait()
        except (asyncio.TimeoutError, TimeoutError):
            proc.kill()
            try:
                await proc.wait()
            except ProcessLookupError:
                pass

        if on_progress is not None:
            await on_progress(100, "sql injection probe complete")
        return "".join(out)

    def parse(self, raw: str) -> list[NormalizedFinding]:
        if not raw:
            return []

        dbms = None
        dbms_match = _DBMS_RE.search(raw)
        if dbms_match:
            dbms = dbms_match.group(1).strip()

        findings: list[NormalizedFinding] = []
        current: Optional[dict] = None

        def flush() -> None:
            nonlocal current
            if current and current["param"]:
                finding = self._to_finding(current, dbms)
                if finding is not None:
                    findings.append(finding)
            current = None

        for line in raw.splitlines():
            text = line.strip()
            param_match = _PARAM_RE.match(text)
            if param_match:
                flush()
                current = {
                    "param": param_match.group(1).strip(),
                    "place": param_match.group(2).strip(),
                    "types": [],
                    "payloads": [],
                }
                continue
            if current is None:
                continue
            type_match = _TYPE_RE.match(text)
            if type_match:
                current["types"].append(type_match.group(1).strip())
                continue
            if _TITLE_RE.match(text):
                continue
            payload_match = _PAYLOAD_RE.match(text)
            if payload_match:
                current["payloads"].append(payload_match.group(1).strip())
                continue
            # A delimiter or a fresh log line ends the current injection block.
            if text.startswith("---") or text.startswith("["):
                flush()

        flush()
        return findings

    def _to_finding(self, info: dict, dbms: Optional[str]) -> Optional[NormalizedFinding]:
        param = info["param"]
        place = info["place"]
        evidence_bits = []
        if info["types"]:
            evidence_bits.append("techniques: " + ", ".join(info["types"]))
        if info["payloads"]:
            evidence_bits.append("payload: " + info["payloads"][0])
        if dbms:
            evidence_bits.append("dbms: " + dbms)
        evidence = "; ".join(evidence_bits) or None

        try:
            return NormalizedFinding(
                engine="sqlmap",
                vuln_type="sql-injection",
                severity=Severity.HIGH,
                title=f"SQL injection in '{param}' ({place})",
                location=self._last_target,
                affected_param=param,
                evidence=evidence,
                cwe_id="CWE-89",
                owasp_category=owasp_for_cwe(89),
                remediation=(
                    "Use parameterized queries / prepared statements and validate "
                    "and escape all user-supplied input."
                ),
            )
        except Exception:  # noqa: BLE001
            return None
