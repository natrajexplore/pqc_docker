"""Golden fixtures: real captures replayed through tshark -> normalizer -> assertions -> verdict.

Each pcap in fixtures/ is named after the scenario that produced it. The scenario's own
wire assertions must pass on it, and the handshake size must match the observed
numbers recorded in the scenario's expected_numbers. Skipped where tshark is absent
(run inside the backend image: see docs/IMPLEMENTATION_PLAN.md).
"""
import asyncio
import shutil
from pathlib import Path

import pytest

from app.analyzer import deep
from app.analyzer.normalize import Endpoint, Normalizer
from app.analyzer.verdict import compute_metrics, compute_verdict, evaluate
from app.scenarios import ScenarioStore

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("*.pcapng"))
EXPECTED_KEX = {
    "ipsec-kex-classical": "classical",
    "ipsec-kex-hybrid-mlkem768": "pq-hybrid",
    "tls-kex-hybrid": "pq-hybrid",
    "ssh-kex-default": "pq-hybrid",
}

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")


@pytest.fixture(scope="module")
def store() -> ScenarioStore:
    s = ScenarioStore(ROOT / "scenarios")
    s.load()
    return s


@pytest.mark.parametrize("pcap", FIXTURES, ids=lambda p: p.stem)
def test_fixture_replays_to_the_recorded_verdict(pcap: Path, store: ScenarioStore):
    sc = store.get(pcap.stem)
    assert sc, f"fixture {pcap.name} has no scenario"
    left, right = sc.endpoints["left"], sc.endpoints["right"]
    norm = Normalizer(Endpoint(name=left.name, ip=left.ip), Endpoint(name=right.name, ip=right.ip))
    packets = []
    for i, layers in enumerate(asyncio.run(deep.ek_from_file(pcap)), 1):
        p = norm("fixture", layers)
        p.n = i
        packets.append(p)

    metrics = compute_metrics(packets)
    wire = [a.model_dump() for a in sc.assertions if a.kind != "step_output"]  # no step outputs offline
    results = evaluate(wire, packets, metrics, {})
    assert all(r.passed for r in results), [f"{r.id}: {r.message}" for r in results if not r.passed]

    verdict = compute_verdict(metrics, sc.declared, results)
    assert verdict.key_exchange.status == EXPECTED_KEX[sc.id]
    assert verdict.key_exchange.evidence == "wire"
    en = sc.expected_numbers
    if sc.protocol == "tls":
        assert metrics.handshake_bytes == en["hello_frames_bytes"]
        assert metrics.protocol["tls"]["server_key_share_len"] == en["server_key_share_bytes_observed"]
    else:
        assert metrics.handshake_bytes == en["handshake_bytes"]
        if "handshake_frames" in en:
            assert metrics.handshake_frames == en["handshake_frames"]
