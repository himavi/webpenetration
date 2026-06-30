"""Engine adapters and the registry the orchestrator runs."""

from app.adapters.base import EngineAdapter
from app.adapters.nuclei import NucleiAdapter

__all__ = ["EngineAdapter", "NucleiAdapter", "get_adapters"]


def get_adapters() -> list[EngineAdapter]:
    """Return one instance of every known adapter.

    The orchestrator filters these by scan type and availability, so it is safe
    to list adapters whose engine may not be installed in a given environment.
    """
    return [NucleiAdapter()]
