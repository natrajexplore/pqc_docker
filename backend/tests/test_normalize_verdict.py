"""Normalizer + verdict tests driven by synthetic tshark EK documents.

Once phase 3 produces real captures, add golden tests that replay
backend/tests/fixtures/*.pcapng through `tshark -T ek` (see test_fixtures.py).
"""
from app.analyzer.normalize import Endpoint, Normalizer
from app.analyzer.verdict import compute_metrics, compute_verdict, evaluate
from tests import ike_builder as b

I, R = "172.30.0.2", "172.30.0.3"


def ek(**fields):
    """Build an EK 'layers' dict; values become single-element lists like tshark's."""
    out = {}
    for k, v in fields.items():
        out[k] = v if isinstance(v, list) else [str(v)]
    return out


def ike_frame(n, t, src, dst, raw: bytes):
    return ek(frame_number=n, frame_time_epoch=t, frame_len=len(raw) + 42, frame_protocols="eth:ethertype:ip:udp:isakmp",
              ip_src=src, ip_dst=dst, udp_srcport=500, udp_dstport=500, udp_payload=raw.hex(":"))


def norm(frames, left=I, right=R):
    n = Normalizer(Endpoint(name="initiator", ip=left), Endpoint(name="responder", ip=right))
    pkts = [n("cap", f) for f in frames]
    for i, p in enumerate(pkts, 1):
        p.n = i
    return pkts


def hybrid_response() -> bytes:
    # Responder echoes the selected proposal including ADDKE1 ML-KEM-768
    sa = b.proposal(1, [b.transform(1, 20, key_len=256), b.transform(2, 5), b.transform(4, 31), b.transform(6, 36, last=True)])
    import struct
    ke = struct.pack("!HH", 31, 0) + b"\x01" * 32
    chain = b.payload(34, sa) + b.payload(40, ke) + b.payload(0, b"\x02" * 32)
    return b.message(34, 33, chain, initiator=False, response=True, rspi=b"\x22" * 8)


def test_ipsec_hybrid_run_is_green_kex_and_assertions_pass():
    frames = [
        ike_frame(1, 1000.000, I, R, b.hybrid_sa_init_request()),
        ike_frame(2, 1000.004, R, I, hybrid_response()),
        ike_frame(3, 1000.010, I, R, b.intermediate_fragment(1, 2)),
        ike_frame(4, 1000.011, I, R, b.intermediate_fragment(2, 2, 150)),
        ike_frame(5, 1000.020, R, I, b.intermediate_sk_response()),
        ek(frame_number=6, frame_time_epoch=1000.1, frame_len=150, frame_protocols="eth:ethertype:ip:esp",
           ip_src=I, ip_dst=R, esp_spi="0xc1a0b2c3", esp_sequence=1),
    ]
    pkts = norm(frames)
    assert pkts[0].direction == "l2r" and pkts[1].direction == "r2l"
    assert "pq-kex-offer" in pkts[0].tags and "pq-kex" in pkts[1].tags
    assert pkts[2].proto == "IKEv2" and "fragment" in pkts[2].tags
    assert pkts[5].proto == "ESP" and pkts[5].kind == "data"

    m = compute_metrics(pkts)
    ike = m.protocol["ike"]
    assert ike["exchanges"]["IKE_INTERMEDIATE"] == 3
    assert ike["selected_additional_ke"] == {"ADDKE1": ["ML_KEM_768"]}
    assert m.fragments == 2 and m.flights == 4 and ike["esp_packets"] == 1

    spec = [
        {"id": "kex-mlkem", "kind": "ikev2.selected_additional_ke", "expect": {"methods": ["ML_KEM_768"]}},
        {"id": "intermediate", "kind": "ikev2.exchange_count", "expect": {"exchange": "IKE_INTERMEDIATE", "min": 2}},
        {"id": "esp", "kind": "count", "expect": {"proto": "ESP", "min": 1}},
        {"id": "auth-psk", "kind": "step_output", "expect": {"step": "list-sas", "regex": "KE1_ML_KEM_768"}},
    ]
    results = evaluate(spec, pkts, m, {"list-sas": "AES_GCM_16-256/PRF_HMAC_SHA2_256/CURVE_25519/KE1_ML_KEM_768"})
    assert all(r.passed for r in results), [r.message for r in results]

    v = compute_verdict(m, {"authentication": "classical", "authentication_algorithm": "PSK"}, results)
    assert v.key_exchange.status == "pq-hybrid" and v.key_exchange.evidence == "wire"
    assert "ML_KEM_768" in v.key_exchange.algorithm
    assert v.color == "amber"          # PQ key exchange, classical (PSK) authentication


def test_ipsec_classical_run_is_red():
    frames = [ike_frame(1, 1.0, I, R, b.hybrid_sa_init_request()), ike_frame(2, 1.01, R, I, b.classical_sa_init_response())]
    pkts = norm(frames)
    m = compute_metrics(pkts)
    v = compute_verdict(m, {}, [])
    assert v.key_exchange.status == "classical" and v.color == "red"


TC, TS = "172.32.0.3", "172.32.0.2"


def tls_frame(n, t, src, dst, **tls):
    return ek(frame_number=n, frame_time_epoch=t, frame_len=tls.pop("flen", 300), frame_protocols="eth:ethertype:ip:tcp:tls",
              ip_src=src, ip_dst=dst, **tls)


def test_tls_hybrid_and_downgrade():
    hybrid = norm([
        tls_frame(1, 1.0, TC, TS, flen=1600, tls_handshake_type="1",
                  tls_handshake_extensions_supported_group=["4588", "29"],
                  tls_handshake_extensions_key_share_group=["4588", "29"],
                  tls_handshake_extensions_key_share_key_exchange_length=["1216", "32"]),
        tls_frame(2, 1.002, TS, TC, flen=1400, tls_handshake_type="2",
                  tls_handshake_extensions_supported_version="0x0304",
                  tls_handshake_extensions_key_share_group="4588",
                  tls_handshake_extensions_key_share_key_exchange_length="1120"),
        tls_frame(3, 1.01, TC, TS, flen=120, tls_record_content_type="23"),
    ], left=TC, right=TS)
    assert "pq-kex-offer" in hybrid[0].tags and "X25519MLKEM768:1216B" in hybrid[0].label
    assert "pq-kex" in hybrid[1].tags and hybrid[2].kind == "data"
    m = compute_metrics(hybrid)
    assert m.protocol["tls"]["server_group"] == "X25519MLKEM768"
    assert m.protocol["tls"]["server_key_share_len"] == 1120
    v = compute_verdict(m, {}, [])
    assert v.key_exchange.status == "pq-hybrid"

    downgraded = norm([
        tls_frame(1, 1.0, TC, TS, tls_handshake_type="1", tls_handshake_extensions_key_share_group=["4588"],
                  tls_handshake_extensions_key_share_key_exchange_length=["1216"]),
        tls_frame(2, 1.002, TS, TC, tls_handshake_type="2", tls_handshake_version="0x0303"),
    ], left=TC, right=TS)
    assert "downgrade" in downgraded[1].tags
    v = compute_verdict(compute_metrics(downgraded), {}, [])
    assert v.key_exchange.status == "downgraded" and v.color == "red"


def test_ssh_negotiation_from_both_kexinits():
    SC, SS = "172.33.0.3", "172.33.0.2"
    pkts = norm([
        ek(frame_number=1, frame_time_epoch=1.0, frame_len=1500, frame_protocols="eth:ethertype:ip:tcp:ssh",
           ip_src=SC, ip_dst=SS, ssh_message_code="20",
           ssh_kex_algorithms="mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256"),
        ek(frame_number=2, frame_time_epoch=1.001, frame_len=1100, frame_protocols="eth:ethertype:ip:tcp:ssh",
           ip_src=SS, ip_dst=SC, ssh_message_code="20",
           ssh_kex_algorithms="curve25519-sha256,mlkem768x25519-sha256"),
    ], left=SC, right=SS)
    m = compute_metrics(pkts)
    # client preference wins (RFC 4253 7.1), even though the server lists curve25519 first
    assert m.protocol["ssh"]["negotiated_kex"] == "mlkem768x25519-sha256"
    assert compute_verdict(m, {}, []).key_exchange.status == "pq-hybrid"


def test_ssh_composite_host_key_is_wire_evidence():
    SC, SS = "172.33.0.3", "172.33.0.2"
    alg = "ssh-mldsa44-ed25519@openssh.com"
    pkts = norm([
        ek(frame_number=1, frame_time_epoch=1.0, frame_len=1500, frame_protocols="eth:ethertype:ip:tcp:ssh",
           ip_src=SC, ip_dst=SS, ssh_message_code="20", ssh_kex_algorithms="mlkem768x25519-sha256",
           ssh_server_host_key_algorithms=alg),
        ek(frame_number=2, frame_time_epoch=1.001, frame_len=1100, frame_protocols="eth:ethertype:ip:tcp:ssh",
           ip_src=SS, ip_dst=SC, ssh_message_code="20", ssh_kex_algorithms="mlkem768x25519-sha256",
           ssh_server_host_key_algorithms=f"{alg},ssh-ed25519"),
    ], left=SC, right=SS)
    m = compute_metrics(pkts)
    assert m.protocol["ssh"]["negotiated_host_key"] == alg
    v = compute_verdict(m, {"authentication": "classical"}, [])
    assert v.authentication.status == "pq" and v.authentication.evidence == "wire"
    assert v.color == "green"


def test_refused_downgrade_is_green():
    v = compute_verdict(compute_metrics([]), {"key_exchange": "refused"}, [])
    assert v.key_exchange.status == "refused" and v.color == "green"


def test_unknown_assertion_kind_fails_cleanly():
    res = evaluate([{"id": "x", "kind": "nope"}], [], compute_metrics([]), {})
    assert not res[0].passed and "unknown assertion" in res[0].message


def esp_frame(n, t, src, dst):
    return ek(frame_number=n, frame_time_epoch=t, frame_len=154, frame_protocols="eth:ethertype:ip:esp",
              ip_src=src, ip_dst=dst, esp_spi="0xc0ffee01", esp_sequence=n)


def icmp_frame(n, t, src, dst):
    return ek(frame_number=n, frame_time_epoch=t, frame_len=98, frame_protocols="eth:ethertype:ip:icmp:data",
              ip_src=src, ip_dst=dst)


NO_ICMP = [{"id": "no-cleartext-icmp", "kind": "count", "expect": {"proto": "ICMP", "max": 0}}]


def test_kernel_decap_copy_of_esp_is_not_a_wire_leak():
    # as captured in the responder's netns: inbound ESP, then the kernel's decrypted
    # re-injection with the identical timestamp; the reply leaves as ESP only
    pkts = norm([esp_frame(1, 10.0, I, R), icmp_frame(2, 10.0, I, R), esp_frame(3, 10.0004, R, I)])
    assert pkts[1].tags == ["decap-copy"] and pkts[1].kind == "other"
    assert compute_metrics(pkts).data_frames == 2
    assert evaluate(NO_ICMP, pkts, compute_metrics(pkts), {})[0].passed


def test_cleartext_leak_is_still_caught():
    # no ESP to pair with, wrong direction, too late, or one ESP claimed twice: all real cleartext
    for frames in ([icmp_frame(1, 10.0, I, R)],
                   [esp_frame(1, 10.0, I, R), icmp_frame(2, 10.0, R, I)],
                   [esp_frame(1, 10.0, I, R), icmp_frame(2, 10.01, I, R)],
                   [esp_frame(1, 10.0, I, R), icmp_frame(2, 10.0, I, R), icmp_frame(3, 10.0, I, R)]):
        pkts = norm(frames)
        assert "cleartext" in pkts[-1].tags
        assert not evaluate(NO_ICMP, pkts, compute_metrics(pkts), {})[0].passed
