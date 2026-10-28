"""PQC WireScope API.

REST (all under /api, proxied by the frontend's nginx):
    GET  /api/health
    GET  /api/stacks                       running lab containers + agent health
    GET  /api/scenarios                    catalogue with availability
    POST /api/scenarios/reload             re-read scenarios/*.yaml
    POST /api/runs        {scenario_id}    start a run -> {run_id}
    GET  /api/runs                         run summaries (newest first)
    GET  /api/runs/{id}                    one run (no packets)
    GET  /api/runs/{id}/packets            normalized packets
    GET  /api/runs/{id}/packets/{n}        full dissection tree + hex for packet n
    GET  /api/runs/{id}/pcap               download the pcapng
    POST /api/runs/{id}/abort
    GET  /api/compare?a=..&b=..            side-by-side metrics of two runs
    POST /api/imports                      upload a pcap (e.g. Cisco EPC export) and analyze it
WebSocket:
    /ws/runs/{id}                          replay + live events (see orchestrator.py)
"""
from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from .analyzer import deep
from .analyzer.normalize import Normalizer
from .analyzer.verdict import compute_metrics, compute_verdict
from .bus import RunBus
from .capture_client import CaptureClient
from .config import settings
from .docker_exec import DockerExec
from .middleware import GuardAndLog, configure_logging
from .models import Run, RunRequest
from .orchestrator import Orchestrator
from .scenarios import ScenarioStore

configure_logging(settings.log_level, settings.log_format)
log = logging.getLogger("pqcw")

store = ScenarioStore(settings.scenario_dir)
bus = RunBus()
STATE: dict = {}

MAX_IMPORT_BYTES = 50 * 2**20
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,96}$")


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.load()
    docker = DockerExec(settings.project)
    orch = Orchestrator(store, docker, bus, settings)
    orch.load_history()
    STATE.update(docker=docker, orch=orch)
    yield


app = FastAPI(title="PQC WireScope", version="0.1.0", lifespan=lifespan)
app.add_middleware(GuardAndLog, allowed_hosts=set(settings.allowed_hosts))


def _orch() -> Orchestrator:
    return STATE["orch"]


def _run(run_id: str) -> Run:
    if not RUN_ID_RE.match(run_id):
        raise HTTPException(400, "bad run id")
    run = _orch().runs.get(run_id)
    if not run:
        raise HTTPException(404, "no such run")
    return run


# ------------------------------------------------------------------ meta --
@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "scenarios": len(store.all()), "scenario_errors": store.errors}


@app.get("/api/stacks")
async def stacks() -> dict:
    running = await STATE["docker"].running()
    agents = {}
    for sc in store.all():
        if sc.capture.agent in agents or sc.capture.agent not in running:
            continue
        try:
            agents[sc.capture.agent] = await CaptureClient(sc.capture.host, settings.agent_port,
                                                           settings.agent_token).health()
        except Exception as exc:
            agents[sc.capture.agent] = {"error": str(exc)}
    return {"running": sorted(running), "agents": agents}


@app.get("/api/scenarios")
async def scenarios() -> list[dict]:
    running = await STATE["docker"].running()
    return [store.info(sc, running).model_dump() for sc in store.all()]


@app.post("/api/scenarios/reload")
async def reload_scenarios() -> dict:
    store.load()
    return {"loaded": len(store.all()), "errors": store.errors}


# ------------------------------------------------------------------ runs --
@app.post("/api/runs")
async def start_run(req: RunRequest) -> dict:
    sc = store.get(req.scenario_id)
    if not sc:
        raise HTTPException(404, "unknown scenario")
    running = await STATE["docker"].running()
    info = store.info(sc, running)
    if not info.available:
        raise HTTPException(409, f"stack not running, missing: {', '.join(info.missing)} "
                                 f"(start it with: make up PROFILES=\"{sc.stack}\")")
    try:
        run = await _orch().start(sc)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"run_id": run.run_id}


@app.get("/api/runs")
async def list_runs(limit: int = Query(50, ge=1, le=1000)) -> list[dict]:
    runs = sorted(_orch().runs.values(), key=lambda r: r.created_at, reverse=True)[:limit]
    return [r.summary() for r in runs]


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str) -> dict:
    return _run(run_id).summary()


@app.get("/api/runs/{run_id}/packets")
async def get_packets(run_id: str) -> list[dict]:
    return [p.model_dump() for p in _run(run_id).packets]


@app.get("/api/runs/{run_id}/packets/{n}")
async def get_packet_detail(run_id: str, n: int, decrypt: bool = False) -> dict:
    run = _run(run_id)
    pkt = next((p for p in run.packets if p.n == n), None)
    if not pkt or not run.pcap_files:
        raise HTTPException(404, "no such packet")
    pcap = Path(run.pcap_files[0])
    keylog = Path(run.keylog_file) if (decrypt and run.keylog_file and settings.allow_tls_keylog) else None
    try:
        detail = await deep.packet_detail(pcap, pkt.frame, keylog)
    except (LookupError, RuntimeError) as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"packet": pkt.model_dump(), **detail}


@app.get("/api/runs/{run_id}/pcap")
async def download_pcap(run_id: str) -> FileResponse:
    run = _run(run_id)
    if not run.pcap_files or not Path(run.pcap_files[0]).exists():
        raise HTTPException(404, "no capture file")
    path = Path(run.pcap_files[0]).resolve()
    if settings.capture_dir.resolve() not in path.parents:
        raise HTTPException(403, "capture outside capture dir")
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=f"{run.run_id}.pcapng")


@app.post("/api/runs/{run_id}/abort")
async def abort_run(run_id: str) -> dict:
    _run(run_id)
    _orch().abort(run_id)
    return {"aborting": run_id}


@app.get("/api/compare")
async def compare(a: str = Query(...), b: str = Query(...)) -> dict:
    ra, rb = _run(a), _run(b)
    if not ra.metrics or not rb.metrics:
        raise HTTPException(409, "both runs must be analyzed")

    def side(r: Run) -> dict:
        return {"run_id": r.run_id, "scenario": r.scenario_title, "verdict": r.verdict.model_dump() if r.verdict else None,
                "metrics": r.metrics.model_dump() if r.metrics else None}

    ma, mb = ra.metrics, rb.metrics
    delta = {k: getattr(mb, k) - getattr(ma, k) for k in
             ("handshake_frames", "handshake_bytes", "flights", "fragments", "largest_frame", "handshake_duration_ms")}
    ratio = round(mb.handshake_bytes / ma.handshake_bytes, 2) if ma.handshake_bytes else None
    return {"a": side(ra), "b": side(rb), "delta": delta, "bytes_ratio": ratio}


# --------------------------------------------------------------- imports --
@app.post("/api/imports")
async def import_pcap(file: UploadFile = File(...), label: str = "imported capture") -> dict:
    """Analyze a capture taken elsewhere - e.g. an IOS XE Embedded Packet Capture
    exported from a Cisco 8000 router - with the same analyzer as live runs."""
    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-import-{secrets.token_hex(3)}"
    dest = settings.capture_dir / run_id / "imported.pcapng"
    dest.parent.mkdir(parents=True, exist_ok=True)
    size = 0
    with dest.open("wb") as fh:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            if size > MAX_IMPORT_BYTES:
                fh.close()
                dest.unlink(missing_ok=True)
                dest.parent.rmdir()
                raise HTTPException(413, "capture larger than 50 MB")
            fh.write(chunk)
    try:
        docs = await deep.ek_from_file(dest)
    except (RuntimeError, TimeoutError) as exc:
        dest.unlink(missing_ok=True)
        dest.parent.rmdir()
        log.warning("import %s rejected: %s", run_id, exc)
        raise HTTPException(400, f"tshark could not read the file: {exc}") from exc
    norm = Normalizer()
    packets = []
    for i, layers in enumerate(docs, 1):
        p = norm("import", layers)
        p.n = i
        packets.append(p)
    metrics = compute_metrics(packets)
    run = Run(run_id=run_id, scenario_id="import", scenario_title=label[:80], protocol="mixed", group="import",
              status="completed", packets=packets, metrics=metrics, verdict=compute_verdict(metrics, {}, []),
              pcap_files=[str(dest)], imported=True, finished_at=time.time())
    _orch().store_imported(run)
    log.info("import %s: %d bytes, %d packets", run_id, size, len(packets))
    return {"run_id": run_id, "packets": len(packets)}


# ------------------------------------------------------------- websocket --
@app.websocket("/ws/runs/{run_id}")
async def ws_run(ws: WebSocket, run_id: str) -> None:
    if not RUN_ID_RE.match(run_id) or run_id not in _orch().runs:
        await ws.close(code=4404)
        return
    await ws.accept()
    q = bus.subscribe(run_id)
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=20)
            except TimeoutError:
                await ws.send_json({"type": "ping"})
                continue
            await ws.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        bus.unsubscribe(run_id, q)
