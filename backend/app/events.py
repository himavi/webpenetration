"""In-memory pub/sub broker for live scan progress updates.

Each WebSocket subscriber gets its own ``asyncio.Queue``; the orchestrator
publishes progress snapshots keyed by scan id. This keeps everything inside the
single application process (no Redis/broker dependency).
"""

import asyncio
from collections import defaultdict


class ProgressBroker:
    """Fan-out of scan progress events to per-subscriber queues."""

    def __init__(self) -> None:
        self._subscribers: dict[int, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, scan_id: int) -> "asyncio.Queue":
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers[scan_id].add(queue)
        return queue

    def unsubscribe(self, scan_id: int, queue: "asyncio.Queue") -> None:
        subscribers = self._subscribers.get(scan_id)
        if not subscribers:
            return
        subscribers.discard(queue)
        if not subscribers:
            self._subscribers.pop(scan_id, None)

    async def publish(self, scan_id: int, event: dict) -> None:
        for queue in list(self._subscribers.get(scan_id, ())):
            await queue.put(event)


# Module-level singleton shared by the orchestrator and the WebSocket route.
broker = ProgressBroker()
