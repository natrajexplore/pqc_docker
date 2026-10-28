"""Per-run event bus feeding the UI WebSocket. Late subscribers get a full replay."""
from __future__ import annotations

import asyncio
from collections import defaultdict


class RunBus:
    def __init__(self, max_history: int = 50_000):
        self.history: dict[str, list[dict]] = defaultdict(list)
        self.subs: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self.max_history = max_history

    def publish(self, run_id: str, event: dict) -> None:
        event = {"run_id": run_id, **event}
        hist = self.history[run_id]
        if len(hist) < self.max_history:
            hist.append(event)
        for q in list(self.subs[run_id]):
            q.put_nowait(event)

    def subscribe(self, run_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        for e in self.history.get(run_id, []):
            q.put_nowait(e)
        self.subs[run_id].add(q)
        return q

    def unsubscribe(self, run_id: str, q: asyncio.Queue) -> None:
        self.subs[run_id].discard(q)
