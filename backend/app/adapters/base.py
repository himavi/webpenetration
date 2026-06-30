"""The engine adapter interface.

Every security engine (Nuclei, ZAP, sqlmap, Nikto, schemathesis, Semgrep, ...)
implements this interface so the orchestrator can run them uniformly and persist
their output as the unified ``NormalizedFinding`` shape from the data layer.
"""

from abc import ABC, abstractmethod

from app.models import ScanType
from app.schemas import NormalizedFinding


class EngineAdapter(ABC):
    """Common contract implemented by every engine adapter."""

    #: Short, stable identifier recorded on each finding (e.g. "nuclei").
    name: str = "engine"

    #: Which scan types this adapter applies to (DAST for live targets, etc.).
    supported_scan_types: tuple[ScanType, ...] = (ScanType.DAST,)

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the engine can run (e.g. its binary is installed)."""

    @abstractmethod
    async def run(self, target: str) -> str:
        """Execute the engine against the target and return its raw output."""

    @abstractmethod
    def parse(self, raw: str) -> list[NormalizedFinding]:
        """Convert raw engine output into a list of unified findings."""

    def supports(self, scan_type: ScanType) -> bool:
        """Whether this adapter should run for the given scan type."""
        return scan_type in self.supported_scan_types
