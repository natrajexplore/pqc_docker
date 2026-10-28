"""Run-level analysis: metrics, the two-pillar PQC verdict, and assertions.

The verdict is always split by pillar, because that is the lesson of the
upstream labs and of Cisco's rollout: key exchange (harvest-now-decrypt-later,
urgent) and authentication (future forgery, slower) move independently.

Evidence is labelled by where it came from:
  wire      - seen in cleartext handshake bytes (strongest)
  endpoint  - reported by the endpoint software (swanctl, ssh -v, wpa log, cert files)
  declared  - only what the scenario says it configured (weakest; shown amber)
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, Field

from . import codepoints as cp
from .normalize import NormalizedPacket


class PillarVerdict(BaseModel):
    status: str = "unknown"          # pq-hybrid | pq-ppk | pq | classical | downgraded | unknown
    algorithm: str | None = None
    evidence: str = "declared"       # wire | endpoint | declared
    detail: str = ""


class Verdict(BaseModel):
    key_exchange: PillarVerdict = Field(default_factory=PillarVerdict)
    authentication: PillarVerdict = Field(default_factory=PillarVerdict)
    color: str = "grey"              # green | amber | red | grey
    summary: str = ""


class AssertionResult(BaseModel):
    id: str
    kind: str
    passed: bool
    message: str
    expected: dict[str, Any] = Field(default_factory=dict)


class Metrics(BaseModel):
    frames_total: int = 0
    handshake_frames: int = 0
    handshake_bytes: int = 0
    data_frames: int = 0
    handshake_duration_ms: float = 0.0
    flights: int = 0                 # direction changes during the handshake + 1
    largest_frame: int = 0
    fragments: int = 0
    protocol: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------- metrics --
def compute_metrics(packets: list[NormalizedPacket]) -> Metrics:
    m = Metrics(frames_total=len(packets))
    hs = [p for p in packets if p.kind == "handshake"]
    m.handshake_frames = len(hs)
    m.handshake_bytes = sum(p.length for p in hs)
    m.data_frames = sum(1 for p in packets if p.kind == "data")
    m.largest_frame = max((p.length for p in hs), default=0)
    m.fragments = sum(1 for p in hs if "fragment" in p.tags)
    if hs:
        m.handshake_duration_ms = round(hs[-1].rel_ms - hs[0].rel_ms, 3)
        flights, last = 0, None
        for p in hs:
            if p.direction != last:
                flights += 1
                last = p.direction
        m.flights = flights
    m.protocol = {
        "ike": _ike_summary(packets),
        "tls": _tls_summary(packets),
        "ssh": _ssh_summary(packets),
        "eap": _eap_summary(packets),
    }
    m.protocol = {k: v for k, v in m.protocol.items() if v}
    return m


def _ike_summary(packets: list[NormalizedPacket]) -> dict:
    ike = [p.detail["ike"] for p in packets if "ike" in p.detail and "exchange" in p.detail["ike"]]
    if not ike:
        return {}
    exchanges: dict[str, int] = {}
    for d in ike:
        exchanges[d["exchange"]] = exchanges.get(d["exchange"], 0) + 1
    init_req = next((d for d in ike if d.get("exchange") == "IKE_SA_INIT" and not d.get("is_response")), None)
    init_resp = next((d for d in ike if d.get("exchange") == "IKE_SA_INIT" and d.get("is_response")), None)
    sizes = {}
    for p in packets:
        d = p.detail.get("ike")
        if d and "exchange" in d:
            key = f"{d['exchange']}:{'resp' if d.get('is_response') else 'req'}"
            sizes[key] = sizes.get(key, 0) + p.length
    return {
        "exchanges": exchanges,
        "offered_ke": _ke_names(init_req, "KE"),
        "offered_additional_ke": (init_req or {}).get("offered_additional_ke", {}),
        "selected_ke": _ke_names(init_resp, "KE"),
        "selected_additional_ke": (init_resp or {}).get("offered_additional_ke", {}),
        "notifies_req": (init_req or {}).get("notifies", []),
        "notifies_resp": (init_resp or {}).get("notifies", []),
        "bytes_by_exchange": sizes,
        "esp_packets": sum(1 for p in packets if p.proto == "ESP"),
    }


def _ke_names(msg: dict | None, ttype: str) -> list[str]:
    if not msg:
        return []
    out: list[str] = []
    for prop in msg.get("proposals", []):
        out += [t["name"] for t in prop.get("transforms", []) if t["type"] == ttype]
    return out


def _tls_summary(packets: list[NormalizedPacket]) -> dict:
    tls = [(p, p.detail["tls"]) for p in packets if "tls" in p.detail]
    if not tls:
        return {}
    ch = next((t for _, t in tls if "ClientHello" in t["handshake_types"]), None)
    sh = next((t for _, t in tls if "ServerHello" in t["handshake_types"]), None)
    ch_pkt = next((p for p, t in tls if "ClientHello" in t["handshake_types"]), None)
    sh_pkt = next((p for p, t in tls if "ServerHello" in t["handshake_types"]), None)
    return {
        "client_groups": (ch or {}).get("supported_groups", []),
        "client_key_shares": (ch or {}).get("key_shares", []),
        "client_signature_algorithms": (ch or {}).get("signature_algorithms", []),
        "server_group": ((sh or {}).get("key_shares") or [{}])[0].get("group"),
        "server_key_share_len": ((sh or {}).get("key_shares") or [{}])[0].get("len"),
        "version": ((sh or {}).get("supported_versions") or [(sh or {}).get("legacy_version")])[0],
        "client_hello_frame_bytes": ch_pkt.length if ch_pkt else None,
        "server_hello_frame_bytes": sh_pkt.length if sh_pkt else None,
        "app_data_records": sum(1 for _, t in tls if "ApplicationData" in t["content_types"]),
    }


def _ssh_summary(packets: list[NormalizedPacket]) -> dict:
    ssh = [p for p in packets if "ssh" in p.detail]
    if not ssh:
        return {}
    kexinits = [p for p in ssh if "KEXINIT" in p.detail["ssh"]["messages"]]
    client = next((p for p in kexinits if p.direction == "l2r"), kexinits[0] if kexinits else None)
    server = next((p for p in kexinits if p.direction == "r2l"), kexinits[1] if len(kexinits) > 1 else None)
    c_kex = client.detail["ssh"]["kex_algorithms"] if client else []
    s_kex = server.detail["ssh"]["kex_algorithms"] if server else []
    negotiated = next((a for a in c_kex if a in s_kex), None)  # RFC 4253 7.1: first client alg the server supports
    # Same rule for the server host key algorithm. The host key itself then travels
    # in cleartext in KEX_ECDH_REPLY, so server authentication is wire-visible in SSH.
    c_hk = client.detail["ssh"]["host_key_algorithms"] if client else []
    s_hk = server.detail["ssh"]["host_key_algorithms"] if server else []
    negotiated_hk = next((a for a in c_hk if a in s_hk), None)
    init = next((p for p in ssh if "KEX_ECDH_INIT" in p.detail["ssh"]["messages"]), None)
    reply = next((p for p in ssh if "KEX_ECDH_REPLY" in p.detail["ssh"]["messages"]), None)
    return {
        "client_kex_first": c_kex[0] if c_kex else None,
        "server_kex_first": s_kex[0] if s_kex else None,
        "negotiated_kex": negotiated,
        "negotiated_host_key": negotiated_hk,
        "kex_init_frame_bytes": init.length if init else None,
        "kex_reply_frame_bytes": reply.length if reply else None,
    }


def _eap_summary(packets: list[NormalizedPacket]) -> dict:
    eap = [p for p in packets if p.proto in ("EAPOL", "EAP", "EAP-TLS", "MKA")]
    if not eap:
        return {}
    return {
        "eapol_frames": len(eap),
        "eap_tls_fragments": sum(1 for p in eap if "fragment" in p.tags),
        "mka_frames": sum(1 for p in eap if p.proto == "MKA"),
        "macsec_frames": sum(1 for p in packets if p.proto == "MACsec"),
        "success": any("Success" in p.label for p in eap),
    }


# --------------------------------------------------------------- verdict --
def compute_verdict(metrics: Metrics, declared: dict[str, str], assertions: list[AssertionResult]) -> Verdict:
    v = Verdict()
    proto = metrics.protocol

    # ---- key exchange: decide from the wire whenever we can
    if ike := proto.get("ike"):
        sel_add = [m for ms in ike.get("selected_additional_ke", {}).values() for m in ms]
        sel_ke = ike.get("selected_ke", [])
        if any(m in cp.PQ_KE_METHODS for m in sel_add + sel_ke):
            v.key_exchange = PillarVerdict(status="pq-hybrid", algorithm="+".join(sel_ke + sel_add), evidence="wire",
                                           detail=f"IKE_INTERMEDIATE x{ike['exchanges'].get('IKE_INTERMEDIATE', 0)}")
        elif "USE_PPK" in ike.get("notifies_resp", []):
            v.key_exchange = PillarVerdict(status="pq-ppk", algorithm="+".join(sel_ke) + " + RFC 8784 PPK", evidence="wire",
                                           detail="USE_PPK negotiated; (EC)DH alone is not quantum-safe, the PPK is")
        elif sel_ke:
            v.key_exchange = PillarVerdict(status="classical", algorithm="+".join(sel_ke), evidence="wire")
    elif tls := proto.get("tls"):
        group = tls.get("server_group")
        if group in cp.PQ_TLS_GROUPS:
            v.key_exchange = PillarVerdict(status="pq-hybrid" if "x25519" in group.lower() or "secp" in group.lower() else "pq",
                                           algorithm=group, evidence="wire", detail=f"{tls.get('version')}")
        elif tls.get("version") == "TLS 1.2":
            v.key_exchange = PillarVerdict(status="downgraded", algorithm="TLS 1.2 (EC)DHE", evidence="wire",
                                           detail="client offered PQ groups but the server capped the version at TLS 1.2")
        elif group:
            v.key_exchange = PillarVerdict(status="classical", algorithm=group, evidence="wire")
    elif ssh := proto.get("ssh"):
        neg = ssh.get("negotiated_kex")
        if neg in cp.PQ_SSH_KEX:
            v.key_exchange = PillarVerdict(status="pq-hybrid", algorithm=neg, evidence="wire")
        elif neg:
            v.key_exchange = PillarVerdict(status="classical", algorithm=neg, evidence="wire")

    if v.key_exchange.status == "unknown" and declared.get("key_exchange"):
        v.key_exchange = PillarVerdict(status=declared["key_exchange"], evidence="declared")

    # ---- authentication: usually encrypted on the wire (IKE_AUTH, TLS 1.3
    # Certificate), so endpoint evidence from a passing assertion is the norm.
    auth_ok = [a for a in assertions if a.kind in ("step_output", "endpoint_auth") and a.id.startswith("auth") and a.passed]
    if declared.get("authentication"):
        v.authentication = PillarVerdict(status=declared["authentication"],
                                         algorithm=declared.get("authentication_algorithm"),
                                         evidence="endpoint" if auth_ok else "declared")
    # TLS with a lab key log: the Certificate message was decrypted, so the
    # certificate algorithms are wire evidence and override the declaration.
    dec = (proto.get("tls") or {}).get("decrypted") or {}
    msgs = dec.get("certificate_messages") or []
    if msgs:
        algs = sorted({a for m in msgs for a in m["algorithms"]})
        pq = any(m["post_quantum"] for m in msgs)
        v.authentication = PillarVerdict(status="pq" if pq else "classical", algorithm=", ".join(algs),
                                         evidence="wire", detail="TLS 1.3 Certificate decrypted with the lab key log")

    ssh_hk = (proto.get("ssh") or {}).get("negotiated_host_key")
    if ssh_hk:
        pq_hk = any(mark in ssh_hk for mark in cp.PQ_SSH_HOSTKEY_MARKERS)
        v.authentication = PillarVerdict(status="pq" if pq_hk else "classical", algorithm=ssh_hk, evidence="wire",
                                         detail="server host key algorithm from both KEXINITs; user auth is encrypted")

    # ---- colour
    kex, auth = v.key_exchange.status, v.authentication.status
    if kex == "refused":
        v.color = "green"          # fail-closed: the downgrade was rejected, nothing classical was negotiated
    elif kex in ("classical", "downgraded"):
        v.color = "red"
    elif kex.startswith("pq") and auth == "pq":
        v.color = "green"
    elif kex.startswith("pq"):
        v.color = "amber"
    if any(not a.passed for a in assertions):
        v.color = "red" if v.color != "grey" else "grey"
    v.summary = f"KEX: {kex}{' ' + v.key_exchange.algorithm if v.key_exchange.algorithm else ''} | AUTH: {auth}" \
                f"{' ' + v.authentication.algorithm if v.authentication.algorithm else ''}"
    return v


# ------------------------------------------------------------ assertions --
AssertionFn = Callable[[dict, list[NormalizedPacket], Metrics, dict[str, str]], tuple[bool, str]]
REGISTRY: dict[str, AssertionFn] = {}


def assertion(kind: str):
    def deco(fn: AssertionFn) -> AssertionFn:
        REGISTRY[kind] = fn
        return fn
    return deco


@assertion("ikev2.selected_additional_ke")
def _a_ike_addke(exp, pkts, m, outs):
    got = [x for xs in m.protocol.get("ike", {}).get("selected_additional_ke", {}).values() for x in xs]
    want = exp.get("methods", [])
    if exp.get("none"):
        return (not got, f"selected additional KE: {got or 'none'}")
    return (all(w in got for w in want), f"selected additional KE: {got or 'none'} (want {want})")


@assertion("ikev2.exchange_count")
def _a_ike_exchange(exp, pkts, m, outs):
    n = m.protocol.get("ike", {}).get("exchanges", {}).get(exp["exchange"], 0)
    lo, hi = exp.get("min", 0), exp.get("max", 10**9)
    return (lo <= n <= hi, f"{exp['exchange']} messages on the wire: {n} (want {lo}..{hi if hi < 10**9 else 'inf'})")


@assertion("ikev2.notify")
def _a_ike_notify(exp, pkts, m, outs):
    ike = m.protocol.get("ike", {})
    seen = set(ike.get("notifies_req", [])) | set(ike.get("notifies_resp", []))
    return (exp["notify"] in seen, f"IKE_SA_INIT notifies: {sorted(seen)}")


@assertion("tls.server_group")
def _a_tls_group(exp, pkts, m, outs):
    g = m.protocol.get("tls", {}).get("server_group")
    if "not" in exp:
        return (g != exp["not"], f"ServerHello group: {g}")
    return (g == exp["group"], f"ServerHello group: {g} (want {exp['group']})")


@assertion("tls.version")
def _a_tls_version(exp, pkts, m, outs):
    v = m.protocol.get("tls", {}).get("version")
    return (v == exp["version"], f"negotiated version: {v} (want {exp['version']})")


@assertion("tls.client_offers_group")
def _a_tls_offer(exp, pkts, m, outs):
    shares = [k["group"] for k in m.protocol.get("tls", {}).get("client_key_shares", [])]
    return (exp["group"] in shares, f"ClientHello key_shares: {shares}")


@assertion("tls.decrypted_cert_pq")
def _a_tls_cert_pq(exp, pkts, m, outs):
    msgs = ((m.protocol.get("tls") or {}).get("decrypted") or {}).get("certificate_messages") or []
    if not msgs:
        return (False, "no decrypted Certificate message (key log missing or decryption failed)")
    pq = any(x["post_quantum"] for x in msgs)
    want = exp.get("post_quantum", True)
    algs = sorted({a for x in msgs for a in x["algorithms"]})
    return (pq == want, f"certificate algorithms on the wire: {algs}")


@assertion("ssh.negotiated_kex")
def _a_ssh_kex(exp, pkts, m, outs):
    neg = m.protocol.get("ssh", {}).get("negotiated_kex")
    return (neg == exp["kex"], f"negotiated kex (from both KEXINITs): {neg} (want {exp['kex']})")


@assertion("ssh.negotiated_host_key")
def _a_ssh_hostkey(exp, pkts, m, outs):
    hk = m.protocol.get("ssh", {}).get("negotiated_host_key")
    if "contains" in exp:
        return (bool(hk) and exp["contains"] in hk, f"negotiated host key algorithm: {hk}")
    return (hk == exp["algorithm"], f"negotiated host key algorithm: {hk} (want {exp['algorithm']})")


@assertion("eap.frames")
def _a_eap_frames(exp, pkts, m, outs):
    n = m.protocol.get("eap", {}).get("eapol_frames", 0)
    lo, hi = exp.get("min", 0), exp.get("max", 10**9)
    return (lo <= n <= hi, f"EAPOL frames: {n} (want {lo}..{hi if hi < 10**9 else 'inf'})")


@assertion("count")
def _a_count(exp, pkts, m, outs):
    # decap-copy frames are the receiver's kernel re-injecting decrypted ESP: not wire frames
    n = sum(1 for p in pkts if p.proto == exp["proto"] and "decap-copy" not in p.tags
            and (not exp.get("tag") or exp["tag"] in p.tags))
    lo, hi = exp.get("min", 0), exp.get("max", 10**9)
    return (lo <= n <= hi, f"{exp['proto']} frames{' tagged ' + exp['tag'] if exp.get('tag') else ''}: {n}")


@assertion("step_output")
def _a_step_output(exp, pkts, m, outs):
    text = outs.get(exp["step"], "")
    ok = re.search(exp["regex"], text, re.MULTILINE) is not None
    if exp.get("absent"):
        ok = not ok
    return (ok, f"step '{exp['step']}' output {'lacks' if exp.get('absent') else 'matches'} /{exp['regex']}/: {ok}")


def evaluate(spec: list[dict], packets: list[NormalizedPacket], metrics: Metrics,
             step_outputs: dict[str, str]) -> list[AssertionResult]:
    results: list[AssertionResult] = []
    for a in spec:
        fn = REGISTRY.get(a["kind"])
        if not fn:
            results.append(AssertionResult(id=a["id"], kind=a["kind"], passed=False,
                                           message=f"unknown assertion kind {a['kind']}", expected=a.get("expect", {})))
            continue
        try:
            ok, msg = fn(a.get("expect", {}), packets, metrics, step_outputs)
        except Exception as exc:  # a bad expectation is a failed assertion, not a crash
            ok, msg = False, f"error: {exc}"
        results.append(AssertionResult(id=a["id"], kind=a["kind"], passed=ok, message=msg, expected=a.get("expect", {})))
    return results
