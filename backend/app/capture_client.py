"""Talk to capture agents: start/stop over HTTP, packet stream over WebSocket."""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable

import httpx
import websockets

log = logging.getLogger(__name__)

PacketHandler = Callable[[dict], Awaitable[None] | None]


class CaptureClient:
    def __init__(self, host: str, port: int, token: str):
        self.base = f"http://{host}:{port}"
        self.ws_base = f"ws://{host}:{port}"
        self.headers = {"X-PQCW-Token": token} if token else {}

    async def health(self) -> dict:
        async with httpx.AsyncClient(timeout=3) as c:
            r = await c.get(f"{self.base}/health")
            r.raise_for_status()
            return r.json()

    async def start(self, run_id: str, bpf: str) -> dict:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(f"{self.base}/captures", json={"run_id": run_id, "bpf": bpf}, headers=self.headers)
            if r.status_code >= 400:
                raise RuntimeError(f"agent refused capture start: {r.status_code} {r.text}")
            return r.json()

    async def stop(self, run_id: str) -> dict:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(f"{self.base}/captures/{run_id}/stop", headers=self.headers)
            if r.status_code >= 400:
                raise RuntimeError(f"agent refused capture stop: {r.status_code} {r.text}")
            return r.json()

    async def stream(self, run_id: str, on_packet: PacketHandler) -> int:
        """Consume the agent's stream until its 'end' message. Returns packet count."""
        url = f"{self.ws_base}/captures/{run_id}/stream"
        count = 0
        async with websockets.connect(url, additional_headers=self.headers, max_size=8 * 2**20) as ws:
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") == "end":
                    break
                if msg.get("type") == "packet":
                    count += 1
                    res = on_packet(msg)
                    if asyncio.iscoroutine(res):
                        await res
        return count
