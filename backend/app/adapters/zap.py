"""OWASP ZAP engine adapter.

Talks to a ZAP daemon over its REST API: access the target, spider it, let the
passive scanner drain, run the active scanner, then collect alerts. The whole
run is time-boxed and reports progress through the orchestrator callback. ZAP
alerts (XSS, SSRF, CSRF, missing security headers, ...) are mapped into the
unified finding shape.
"""

import asyncio
import json
import os
import time
from typing import Optional

import httpx

from app.adapters.base import EngineAdapter
from app.adapters.owasp import owasp_for_cwe
from app.models import ScanType, Severity
from app.schemas import NormalizedFinding

# ZAP riskcode: 0 Informational, 1 Low, 2 Medium, 3 High (no "critical").
_RISK_TO_SEVERITY = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
}


class ZapAdapter(EngineAdapter):
    name = "zap"
    supported_scan_types = (ScanType.DAST,)

    def __init__(
        self,
        *,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        overall_timeout: Optional[float] = None,
    ) -> None:
        self.api_url = (api_url or os.getenv("ZAP_API_URL", "http://zap:8090")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.getenv("ZAP_API_KEY", "")
        self.overall_timeout = float(
            overall_timeout if overall_timeout is not None else os.getenv("ZAP_TIMEOUT", "180")
        )

    def _params(self, **kwargs) -> dict:
        if self.api_key:
            kwargs["apikey"] = self.api_key
        return kwargs

    def is_available(self) -> bool:
        try:
            resp = httpx.get(
                f"{self.api_url}/JSON/core/view/version/", params=self._params(), timeout=3.0
            )
            return resp.status_code == 200
        except Exception:  # noqa: BLE001 - any failure means "not reachable"
            return False

    async def run(self, target: str, on_progress=None) -> str:
        deadline = time.monotonic() + self.overall_timeout

        async def report(pct: int, message: str) -> None:
            if on_progress is not None:
                await on_progress(pct, message)

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:

                async def get(path: str, **params):
                    resp = await client.get(f"{self.api_url}{path}", params=self._params(**params))
                    resp.raise_for_status()
                    return resp.json()

                # Make ZAP aware of the target.
                try:
                    await get("/JSON/core/action/accessUrl/", url=target)
                except Exception:  # noqa: BLE001
                    pass

                # Spider (0-30% of this engine's band).
                await report(5, "spidering")
                try:
                    started = await get("/JSON/spider/action/scan/", url=target, recurse="true")
                    spider_id = started.get("scan")
                    while time.monotonic() < deadline:
                        status = await get("/JSON/spider/view/status/", scanId=spider_id)
                        pct = _as_int(status.get("status"))
                        await report(5 + int(pct * 0.25), "spidering")
                        if pct >= 100:
                            break
                        await asyncio.sleep(1.5)
                except Exception:  # noqa: BLE001
                    pass

                # Let the passive scanner finish processing what the spider found.
                await report(32, "passive analysis")
                while time.monotonic() < deadline:
                    try:
                        records = await get("/JSON/pscan/view/recordsToScan/")
                    except Exception:  # noqa: BLE001
                        break
                    if _as_int(records.get("recordsToScan")) <= 0:
                        break
                    await asyncio.sleep(1.0)

                # Active scan (40-95%).
                await report(40, "active scan")
                try:
                    started = await get(
                        "/JSON/ascan/action/scan/", url=target, recurse="true", inScopeOnly="false"
                    )
                    ascan_id = started.get("scan")
                    while time.monotonic() < deadline:
                        status = await get("/JSON/ascan/view/status/", scanId=ascan_id)
                        pct = _as_int(status.get("status"))
                        await report(40 + int(pct * 0.55), "active scan")
                        if pct >= 100:
                            break
                        await asyncio.sleep(2.0)
                    # If we ran out of time, stop the scan rather than leave it running.
                    try:
                        await get("/JSON/ascan/action/stop/", scanId=ascan_id)
                    except Exception:  # noqa: BLE001
                        pass
                except Exception:  # noqa: BLE001
                    pass

                await report(97, "collecting alerts")
                alerts = await get(
                    "/JSON/core/view/alerts/", baseurl=target, start="0", count="5000"
                )
                return json.dumps(alerts)
        except Exception:  # noqa: BLE001 - daemon went away mid-scan; degrade gracefully
            return ""

    def parse(self, raw: str) -> list[NormalizedFinding]:
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        alerts = data.get("alerts") if isinstance(data, dict) else data
        if not isinstance(alerts, list):
            return []
        findings: list[NormalizedFinding] = []
        for alert in alerts:
            finding = self._to_finding(alert)
            if finding is not None:
                findings.append(finding)
        return findings

    @staticmethod
    def _to_finding(alert: dict) -> Optional[NormalizedFinding]:
        name = alert.get("alert") or alert.get("name") or "ZAP Alert"
        severity = _RISK_TO_SEVERITY.get(_as_int(alert.get("riskcode")), Severity.INFO)

        evidence_bits = []
        if alert.get("evidence"):
            evidence_bits.append(f"evidence: {alert['evidence']}")
        if alert.get("attack"):
            evidence_bits.append(f"attack: {alert['attack']}")
        if alert.get("otherinfo"):
            evidence_bits.append(str(alert["otherinfo"]))
        evidence = "; ".join(evidence_bits) or None

        cwe = None
        cwe_int = _as_int(alert.get("cweid"), default=-1)
        if cwe_int > 0:
            cwe = f"CWE-{cwe_int}"

        try:
            return NormalizedFinding(
                engine="zap",
                vuln_type=str(name),
                severity=severity,
                title=str(name),
                location=alert.get("url") or None,
                affected_param=alert.get("param") or None,
                evidence=evidence,
                cwe_id=cwe,
                owasp_category=owasp_for_cwe(cwe),
                remediation=alert.get("solution") or None,
            )
        except Exception:  # noqa: BLE001
            return None


def _as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
