"""Engine adapters and the registry the orchestrator runs."""

from app.adapters.base import EngineAdapter
from app.adapters.nuclei import NucleiAdapter
from app.adapters.zap import ZapAdapter

__all__ = ["EngineAdapter", "NucleiAdapter", "ZapAdapter", "get_adapters"]


def get_adapters() -> list[EngineAdapter]:
    """Return one instance of every known adapter.

    The orchestrator filters these by scan type and availability, so it is safe
    to list adapters whose engine may not be installed/reachable in a given
    environment.
    """
    return [NucleiAdapter(), ZapAdapter()]
