"""The engine adapter interface.

Every security engine (Nuclei, ZAP, sqlmap, Nikto, schemathesis, Semgrep, ...)
implements this interface so the orchestrator can run them uniformly and persist
their output as the unified ``NormalizedFinding`` shape from the data layer.
"""

from abc import ABC, abstractmethod
from typing import Awaitable, Callable, Optional

from app.models import ScanType
from app.schemas import NormalizedFinding

#: Async callback an adapter may await to report fine-grained progress. It
#: receives a percent (0-100, relative to the adapter's own work) and a short
#: human-readable message. The orchestrator maps it into the overall scan bar.
ProgressCallback = Callable[[int, str], Awaitable[None]]


class EngineAdapter(ABC):
    """Common contract implemented by every engine adapter."""

    #: Short, stable identifier recorded on each finding (e.g. "nuclei").
    name: str = "engine"

    #: Which scan types this adapter applies to (DAST for live targets, etc.).
    supported_scan_types: tuple[ScanType, ...] = (ScanType.DAST,)

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the engine can run (e.g. its binary/daemon is reachable)."""

    @abstractmethod
    async def run(self, target: str, on_progress: Optional[ProgressCallback] = None, **kwargs) -> str:
        """Execute the engine against the target and return its raw output.

        ``on_progress`` (optional) may be awaited to report intra-run progress.
        ``kwargs`` may carry extra scan metadata (e.g. ``spec_url`` for API fuzzing).
        """

    @abstractmethod
    def parse(self, raw: str) -> list[NormalizedFinding]:
        """Convert raw engine output into a list of unified findings."""

    def supports(self, scan_type: "ScanType") -> bool:
        """Whether this adapter should run for the given scan type.

        A ``BOTH`` scan runs all adapters (both DAST and SAST).
        """
        from app.models import ScanType as ST

        if scan_type == ST.BOTH:
            return True
        return scan_type in self.supported_scan_types
