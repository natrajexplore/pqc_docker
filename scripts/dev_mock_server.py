"""Serve the built UI with the REAL backend API, but fake Docker + fake capture agent.

Lets the whole stack (orchestrator, analyzer, WebSocket events, UI) run without
containers - useful for UI work and for demos on a machine with no Docker:

    cd frontend && npm run build && cd ..
    pip install -e "backend[dev]"
    cd scripts && python -m uvicorn dev_mock_server:app --port 8765
    # open http://127.0.0.1:8765 and run the IPsec key-exchange scenarios

Only the ipsec stack is "running" in the mock, and every run streams synthetic
IKEv2 frames (classical for *classical* scenarios, hybrid ML-KEM-768 otherwise).
"""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
cap = tempfile.mkdtemp()
os.environ["PQCW_SCENARIO_DIR"] = str(ROOT / "scenarios")
os.environ["PQCW_CAPTURE_DIR"] = cap

from fastapi.staticfiles import StaticFiles  # noqa: E402

from app import main, orchestrator  # noqa: E402
from tests.test_orchestrator import GOOD, FakeAgent, FakeDocker  # noqa: E402


class AllUp(FakeDocker):
    async def running(self):
        names = set()
        for sc in main.store.all():
            if sc.protocol == "ipsec" and sc.stack == "ipsec":
                names |= set(sc.nodes.values()) | {sc.capture.agent}
        return names


from tests import ike_builder as b  # noqa: E402
from tests.test_normalize_verdict import ike_frame  # noqa: E402
from tests.test_orchestrator import FRAMES  # noqa: E402

CLASSICAL = [ike_frame(1, 10.0, "172.30.0.2", "172.30.0.3", b.ppk_sa_init_request().replace(b"\x00\x00\x40\x33", b"\x00\x00\x40\x2e")),
             ike_frame(2, 10.003, "172.30.0.3", "172.30.0.2", b.classical_sa_init_response()),
             ike_frame(3, 10.008, "172.30.0.2", "172.30.0.3", b.message(35, 46, b.payload(35, b"\xaa" * 260), msgid=1, rspi=b"\x22" * 8)),
             ike_frame(4, 10.012, "172.30.0.3", "172.30.0.2", b.message(35, 46, b.payload(36, b"\xbb" * 230), initiator=False, response=True, msgid=1, rspi=b"\x22" * 8))] + FRAMES[5:]


class Agent(FakeAgent):
    async def stream(self, run_id, on_packet):
        await FakeAgent.stopped.wait()
        for f in (CLASSICAL if "classical" in run_id else FRAMES):
            await on_packet({"type": "packet", "agent": "cap-ipsec", "layers": f})
        return 1


orchestrator.CaptureClient = Agent
_orig = main.lifespan


from contextlib import asynccontextmanager  # noqa: E402


@asynccontextmanager
async def lifespan(app):
    async with _orig(app):
        d = AllUp(GOOD)
        main.STATE["docker"] = d
        main.STATE["orch"].docker = d
        yield

main.app.router.lifespan_context = lifespan
main.app.mount("/", StaticFiles(directory=ROOT / "frontend" / "dist", html=True), name="ui")
app = main.app
