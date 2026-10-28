"""Drive a real scenario file through the orchestrator with fake Docker and a fake agent.

Proves the engine (step ordering, templating, expect/regex, capture fan-in,
cleanup, analysis, persistence) without a single container.
"""
import asyncio
import re
from pathlib import Path

from app import orchestrator as orch_mod
from app.bus import RunBus
from app.config import Settings
from app.docker_exec import ExecResult
from app.scenarios import ScenarioStore
from tests import ike_builder as b
from tests.test_normalize_verdict import hybrid_response, ike_frame

ROOT = Path(__file__).resolve().parents[2]
I, R = "172.30.0.2", "172.30.0.3"


class FakeDocker:
    """Answers exec calls from a regex -> output table and records every call."""
    def __init__(self, answers: dict[str, tuple[int, str]]):
        self.answers = answers
        self.calls: list[tuple[str, list[str], bool]] = []

    async def running(self):
        return {"pqcw-ipsec-initiator", "pqcw-ipsec-responder", "pqcw-cap-ipsec"}

    def _answer(self, argv):
        line = " ".join(argv)
        for pat, (rc, out) in self.answers.items():
            if re.search(pat, line):
                return ExecResult(rc, out)
        return ExecResult(0, "")

    async def exec(self, container, argv, env=None, on_output=None):
        self.calls.append((container, argv, False))
        res = self._answer(argv)
        if on_output and res.output:
            on_output(res.output)
        return res

    async def exec_detached(self, container, argv, env=None):
        self.calls.append((container, argv, True))
        return ExecResult(0, "started")


FRAMES = [
    ike_frame(1, 10.000, I, R, b.hybrid_sa_init_request()),
    ike_frame(2, 10.003, R, I, hybrid_response()),
    ike_frame(3, 10.010, I, R, b.intermediate_fragment(1, 2)),
    ike_frame(4, 10.011, I, R, b.intermediate_fragment(2, 2, 150)),
    ike_frame(5, 10.020, R, I, b.intermediate_sk_response()),
] + [
    {"frame_number": [str(6 + i)], "frame_time_epoch": [str(10.1 + i / 100)], "frame_len": ["150"],
     "frame_protocols": ["eth:ethertype:ip:esp"], "ip_src": [I if i % 2 == 0 else R],
     "ip_dst": [R if i % 2 == 0 else I], "esp_spi": ["0xc0ffee01"], "esp_sequence": [str(i // 2 + 1)]}
    for i in range(6)
]


class FakeAgent:
    stopped: asyncio.Event

    def __init__(self, host, port, token):
        self.host = host
        FakeAgent.stopped = asyncio.Event()

    async def start(self, run_id, bpf):
        assert "udp port 500" in bpf
        return {"iface": "eth0", "pcap": f"/captures/{run_id}/cap-ipsec.pcapng"}

    async def stop(self, run_id):
        FakeAgent.stopped.set()
        return {"pcap": f"/captures/{run_id}/cap-ipsec.pcapng", "packets": len(FRAMES), "pcap_bytes": 4096}

    async def stream(self, run_id, on_packet):
        await FakeAgent.stopped.wait()
        for f in FRAMES:
            await on_packet({"type": "packet", "agent": "cap-ipsec", "layers": f})
        return len(FRAMES)


def _run_scenario(tmp_path, answers):
    store = ScenarioStore(ROOT / "scenarios")
    store.load()
    sc = store.get("ipsec-kex-hybrid-mlkem768")
    assert sc, store.errors
    docker = FakeDocker(answers)
    bus = RunBus()
    settings = Settings(capture_dir=tmp_path, run_timeout_s=30, allow_tls_keylog=False)
    orch_mod.CaptureClient = FakeAgent  # type: ignore[misc]
    o = orch_mod.Orchestrator(store, docker, bus, settings)

    async def go():
        run = await o.start(sc)
        await o.tasks[run.run_id]
        return run

    return asyncio.run(go()), docker, bus


GOOD = {
    r"list-algs": (0, "ML_KEM_512[ml]\nML_KEM_768[ml]\nML_KEM_1024[ml]\n"),
    r"--initiate": (0, "[IKE] establishing CHILD_SA pqc-child\ninitiate completed successfully\n"),
    r"--list-sas": (0, "pqc-tunnel: #1, ESTABLISHED, IKEv2\n  AES_GCM_16-256/PRF_HMAC_SHA2_256/CURVE_25519/KE1_ML_KEM_768\n"),
}


def test_hybrid_scenario_end_to_end(tmp_path):
    run, docker, bus = _run_scenario(tmp_path, GOOD)
    assert run.status == "completed", (run.error, [(s.id, s.status, s.message) for s in run.steps])
    assert all(s.status == "ok" for s in run.steps)
    assert len(run.packets) == len(FRAMES)
    assert all(a.passed for a in run.assertions), [(a.id, a.message) for a in run.assertions]
    assert run.verdict.key_exchange.status == "pq-hybrid"
    assert run.verdict.color == "amber"                 # PQ KEX + PSK auth
    # variant files were loaded on both peers, and cleanup ran
    loads = [c for c in docker.calls if "--load-all" in c[1]]
    assert {c[0] for c in loads} == {"pqcw-ipsec-initiator", "pqcw-ipsec-responder"}
    assert any("--terminate" in " ".join(c[1]) for c in docker.calls[-2:])
    # every non-detached exec is wrapped in coreutils timeout
    assert all(c[1][0] == "timeout" for c in docker.calls if not c[2])
    # the run was persisted and the UI got a result event
    assert (tmp_path / run.run_id / "run.json").exists()
    assert any(e["type"] == "run.result" for e in bus.history[run.run_id])


def test_failed_expect_stops_run_and_still_cleans_up(tmp_path):
    bad = dict(GOOD)
    bad[r"--initiate"] = (0, "[IKE] received NO_PROPOSAL_CHOSEN notify error\ninitiate failed\n")
    run, docker, _ = _run_scenario(tmp_path, bad)
    assert run.status == "failed"
    statuses = {s.id: s.status for s in run.steps}
    assert statuses["initiate"] == "failed"
    assert statuses["dataplane"] == "skipped"
    assert any("--terminate" in " ".join(c[1]) for c in docker.calls)   # cleanup still ran
    assert run.verdict is not None                                       # analysis still produced a verdict
