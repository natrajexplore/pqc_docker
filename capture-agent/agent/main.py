"""PQC WireScope capture agent.

One agent per lab, living in the lab node's network namespace. API (mgmt leg only):

    GET  /health                         -> agent name, capture iface, busy flag
    POST /captures        {run_id, bpf}  -> start dumpcap (pcapng) + live tshark
    WS   /captures/{run_id}/stream       -> {"type":"packet",...} ... {"type":"end"}
    POST /captures/{run_id}/stop         -> stop both, return file path + counts

Every request except /health must carry X-PQCW-Token; the agent refuses to start
without PQCW_AGENT_TOKEN.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from .fields import usable_live_fields
from .netinfo import iface_exists, iface_for_subnet

logging.basicConfig(level=os.getenv("PQCW_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("agent")

AGENT_NAME = os.getenv("AGENT_NAME", "cap")
CAPTURE_DIR = Path(os.getenv("CAPTURE_DIR", "/captures"))
TOKEN = os.getenv("PQCW_AGENT_TOKEN", "")
PORT = int(os.getenv("AGENT_PORT", "9100"))
MAX_PACKETS = int(os.getenv("AGENT_MAX_PACKETS", "20000"))

RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
BPF_RE = re.compile(r"^[A-Za-z0-9 ._:/()!&|=<>\[\]-]{0,256}$")


def _resolve_capture_iface() -> str:
    explicit = os.getenv("CAPTURE_IFACE")
    if explicit:
        if not iface_exists(explicit):
            raise SystemExit(f"CAPTURE_IFACE={explicit} not present in this netns")
        return explicit
    subnet = os.getenv("LAB_SUBNET")
    if not subnet:
        raise SystemExit("set CAPTURE_IFACE or LAB_SUBNET")
    found = iface_for_subnet(subnet)
    if not found:
        raise SystemExit(f"no interface with an address in {subnet}")
    return found[0]


def _resolve_bind_addr() -> str:
    subnet = os.getenv("MGMT_SUBNET")
    if not subnet:
        return "127.0.0.1"
    found = iface_for_subnet(subnet)
    if not found:
        raise SystemExit(f"no interface with an address in MGMT_SUBNET={subnet}")
    return found[1]


@dataclass
class Session:
    run_id: str
    bpf: str
    pcap_path: Path
    dumpcap: asyncio.subprocess.Process | None = None
    tshark: asyncio.subprocess.Process | None = None
    packets: list[dict] = field(default_factory=list)
    subscribers: set[asyncio.Queue] = field(default_factory=set)
    started_at: float = field(default_factory=time.time)
    finished: bool = False
    reader_task: asyncio.Task | None = None
    dropped: int = 0

    def broadcast(self, msg: dict) -> None:
        for q in list(self.subscribers):
            q.put_nowait(msg)


class StartRequest(BaseModel):
    run_id: str = Field(..., description="backend run id; becomes the capture directory name")
    bpf: str = Field("", description="capture filter applied to both dumpcap and tshark")


app = FastAPI(title=f"pqcw capture agent ({AGENT_NAME})")
STATE: dict = {"iface": None, "fields": [], "session": None}


def _token_ok(token: str | None) -> bool:
    return bool(TOKEN) and hmac.compare_digest((token or "").encode(), TOKEN.encode())


def _auth(token: str | None, where: str) -> None:
    if not _token_ok(token):
        log.warning("rejected %s: bad or missing agent token", where)
        raise HTTPException(status_code=401, detail="bad agent token")


async def _wait_for_capture_banner(proc: asyncio.subprocess.Process, what: str, timeout: float = 8.0) -> None:
    """dumpcap/tshark print 'Capturing on ...' to stderr once the handle is open."""
    assert proc.stderr is not None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            line = await asyncio.wait_for(proc.stderr.readline(), timeout=deadline - time.monotonic())
        except TimeoutError:
            break
        if not line:
            break
        text = line.decode(errors="replace").strip()
        log.debug("%s: %s", what, text)
        if "Capturing on" in text:
            asyncio.create_task(_drain(proc.stderr, what))
            return
    raise RuntimeError(f"{what} did not start capturing within {timeout}s")


async def _drain(stream: asyncio.StreamReader, what: str) -> None:
    while line := await stream.readline():
        log.debug("%s: %s", what, line.decode(errors="replace").rstrip())


async def _read_tshark(sess: Session) -> None:
    assert sess.tshark and sess.tshark.stdout
    while line := await sess.tshark.stdout.readline():
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "index" in doc:  # EK emits an index line before every document
            continue
        layers = doc.get("layers")
        if not layers:
            continue
        if len(sess.packets) >= MAX_PACKETS:
            sess.dropped += 1
            continue
        pkt = {"type": "packet", "agent": AGENT_NAME, "run_id": sess.run_id, "layers": layers}
        sess.packets.append(pkt)
        sess.broadcast(pkt)
    sess.finished = True
    sess.broadcast({"type": "end", "agent": AGENT_NAME, "run_id": sess.run_id,
                    "count": len(sess.packets), "dropped": sess.dropped})


@app.on_event("startup")
async def _startup() -> None:
    STATE["iface"] = _resolve_capture_iface()
    STATE["fields"] = usable_live_fields()
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    # The backend runs unprivileged (uid 10001) and must write run.json, key logs
    # and imports here. We own the volume root, so chmod needs no capability.
    try:
        CAPTURE_DIR.chmod(0o1777)
    except PermissionError:
        log.warning("could not chmod %s; backend may not be able to write run metadata", CAPTURE_DIR)
    log.info("agent %s capturing on %s with %d live fields", AGENT_NAME, STATE["iface"], len(STATE["fields"]))


@app.get("/health")
async def health() -> dict:
    sess: Session | None = STATE["session"]
    return {
        "agent": AGENT_NAME,
        "iface": STATE["iface"],
        "busy": bool(sess and not sess.finished),
        "run_id": sess.run_id if sess else None,
        "live_fields": len(STATE["fields"]),
    }


@app.post("/captures")
async def start(req: StartRequest, x_pqcw_token: str | None = Header(default=None)) -> dict:
    _auth(x_pqcw_token, "capture start")
    if not RUN_ID_RE.match(req.run_id):
        raise HTTPException(400, "invalid run_id")
    if not BPF_RE.match(req.bpf):
        raise HTTPException(400, "invalid capture filter")
    cur: Session | None = STATE["session"]
    if cur and not cur.finished:
        raise HTTPException(409, f"already capturing run {cur.run_id}")

    run_dir = CAPTURE_DIR / req.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    run_dir.chmod(0o777)  # lab: backend (uid 10001) writes run.json + tls.keylog beside the pcap
    pcap = run_dir / f"{AGENT_NAME}.pcapng"
    iface = STATE["iface"]
    bpf_args = ["-f", req.bpf] if req.bpf else []

    sess = Session(run_id=req.run_id, bpf=req.bpf, pcap_path=pcap)

    # 1) authoritative file
    sess.dumpcap = await asyncio.create_subprocess_exec(
        "dumpcap", "-i", iface, *bpf_args, "-w", str(pcap), "-q",
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
    # dumpcap -q suppresses the banner on some versions; fall back to a short settle
    try:
        await _wait_for_capture_banner(sess.dumpcap, "dumpcap", timeout=3)
    except RuntimeError:
        if sess.dumpcap.returncode is not None:
            raise HTTPException(500, "dumpcap failed to start") from None
        asyncio.create_task(_drain(sess.dumpcap.stderr, "dumpcap"))  # type: ignore[arg-type]

    # 2) live decode stream
    field_args: list[str] = []
    for f in STATE["fields"]:
        field_args += ["-e", f]
    sess.tshark = await asyncio.create_subprocess_exec(
        "tshark", "-l", "-n", "-i", iface, *bpf_args, "-T", "ek", *field_args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        await _wait_for_capture_banner(sess.tshark, "tshark")
    except RuntimeError as exc:
        sess.dumpcap.send_signal(signal.SIGINT)
        raise HTTPException(500, str(exc)) from exc

    sess.reader_task = asyncio.create_task(_read_tshark(sess))
    STATE["session"] = sess
    log.info("run %s: capturing on %s filter=%r -> %s", req.run_id, iface, req.bpf, pcap)
    return {"agent": AGENT_NAME, "run_id": req.run_id, "iface": iface, "pcap": str(pcap)}


@app.websocket("/captures/{run_id}/stream")
async def stream(ws: WebSocket, run_id: str) -> None:
    if not _token_ok(ws.headers.get("x-pqcw-token")):
        log.warning("rejected stream: bad or missing agent token")
        await ws.close(code=4401)
        return
    sess: Session | None = STATE["session"]
    if not sess or sess.run_id != run_id:
        await ws.close(code=4404)
        return
    await ws.accept()
    q: asyncio.Queue = asyncio.Queue()
    # replay what was captured before this subscriber connected
    for pkt in list(sess.packets):
        q.put_nowait(pkt)
    if sess.finished:
        q.put_nowait({"type": "end", "agent": AGENT_NAME, "run_id": run_id, "count": len(sess.packets)})
    sess.subscribers.add(q)
    try:
        while True:
            msg = await q.get()
            await ws.send_json(msg)
            if msg.get("type") == "end":
                break
    except WebSocketDisconnect:
        pass
    finally:
        sess.subscribers.discard(q)
        try:
            await ws.close()
        except RuntimeError:
            pass


async def _stop_proc(proc: asyncio.subprocess.Process | None, name: str) -> None:
    if not proc or proc.returncode is not None:
        return
    proc.send_signal(signal.SIGINT)  # SIGINT lets dumpcap finalise the pcapng
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except TimeoutError:
        log.warning("%s did not exit on SIGINT, killing", name)
        proc.kill()
        await proc.wait()


@app.post("/captures/{run_id}/stop")
async def stop(run_id: str, x_pqcw_token: str | None = Header(default=None)) -> dict:
    _auth(x_pqcw_token, "capture stop")
    sess: Session | None = STATE["session"]
    if not sess or sess.run_id != run_id:
        raise HTTPException(404, "no such capture")
    # small grace period so the last frames of a handshake are flushed
    await asyncio.sleep(0.5)
    await _stop_proc(sess.tshark, "tshark")
    await _stop_proc(sess.dumpcap, "dumpcap")
    if sess.reader_task:
        try:
            await asyncio.wait_for(sess.reader_task, timeout=5)
        except TimeoutError:
            sess.reader_task.cancel()
    size = 0
    if sess.pcap_path.exists():
        sess.pcap_path.chmod(0o644)  # dumpcap writes 0600; the backend must read it
        size = sess.pcap_path.stat().st_size
    log.info("run %s: stopped, %d packets, %d bytes on disk", run_id, len(sess.packets), size)
    return {"agent": AGENT_NAME, "run_id": run_id, "pcap": str(sess.pcap_path),
            "packets": len(sess.packets), "dropped": sess.dropped, "pcap_bytes": size,
            "duration_s": round(time.time() - sess.started_at, 3)}


def main() -> None:
    if not TOKEN:
        # Fail closed: without a token any lab container could drive captures.
        raise SystemExit("PQCW_AGENT_TOKEN is not set - run 'make secrets' and restart the stack")
    bind = _resolve_bind_addr()
    Path("/tmp/agent.addr").write_text(f"{bind}:{PORT}\n")
    log.info("agent %s listening on %s:%d (mgmt leg only)", AGENT_NAME, bind, PORT)
    uvicorn.run(app, host=bind, port=PORT, log_level=os.getenv("PQCW_LOG_LEVEL", "info").lower())


if __name__ == "__main__":
    main()
