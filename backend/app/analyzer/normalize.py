"""Turn one tshark EK document (from a capture agent) into a NormalizedPacket.

EK output renames fields: `tls.handshake.type` arrives as `tls_handshake_type`,
and every value is a list of strings. `F(layers, "tls.handshake.type")` hides
that, accepting either spelling.

The normalizer is deliberately protocol-aware but scenario-agnostic: it labels
and tags what is on the wire. Judging whether a run was "post-quantum" is
verdict.py's job.
"""
from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

from . import codepoints as cp
from . import ikev2

log = logging.getLogger(__name__)


class Endpoint(BaseModel):
    """How to recognise one side of the handshake in a frame."""
    name: str
    ip: str | None = None
    mac: str | None = None


class NormalizedPacket(BaseModel):
    n: int = 0                       # run-wide sequence (assigned by the run)
    frame: int = 0                   # agent-local frame number (pcap index)
    agent: str = ""
    ts: float = 0.0
    rel_ms: float = 0.0
    src: str = ""
    dst: str = ""
    length: int = 0
    proto: str = "OTHER"
    kind: str = "other"              # handshake | data | control | other
    direction: str = "unknown"       # l2r (left->right) | r2l | unknown
    label: str = ""
    info: str = ""
    tags: list[str] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)


# ------------------------------------------------------------ field access --
def _key(name: str) -> str:
    return name.replace(".", "_")


def F(layers: dict, name: str) -> str | None:
    """First value of a field, or None."""
    for k in (name, _key(name)):
        v = layers.get(k)
        if v is None:
            continue
        if isinstance(v, list):
            return str(v[0]) if v else None
        return str(v)
    return None


def FA(layers: dict, name: str) -> list[str]:
    """All values of a field (tshark repeats fields that occur several times)."""
    for k in (name, _key(name)):
        v = layers.get(k)
        if v is None:
            continue
        if isinstance(v, list):
            out: list[str] = []
            for item in v:
                # some tshark versions pack repeated values comma-joined into one string
                out += [s for s in str(item).split(",") if s != ""] if _looks_numeric_list(item) else [str(item)]
            return out
        return [str(v)]
    return []


def _looks_numeric_list(item: Any) -> bool:
    s = str(item)
    return "," in s and all(p.strip().lstrip("0x").isalnum() for p in s.split(","))


def to_int(v: str | None) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(float(v))
    except ValueError:
        return None


def hex_bytes(v: str | None) -> bytes | None:
    if not v:
        return None
    try:
        return bytes.fromhex(v.replace(":", "").replace(" ", ""))
    except ValueError:
        return None


# ------------------------------------------------------------- normalizer --
class Normalizer:
    def __init__(self, left: Endpoint | None = None, right: Endpoint | None = None):
        self.left = left
        self.right = right
        self.t0: float | None = None
        # inbound ESP frames not yet matched to their kernel decapsulation copy, see _mark_decap_copy
        self._esp_unpaired: list[tuple[str, str, float]] = []

    def direction(self, src_ip: str | None, src_mac: str | None) -> str:
        for side, tag in ((self.left, "l2r"), (self.right, "r2l")):
            if not side:
                continue
            if side.ip and src_ip == side.ip:
                return tag
            if side.mac and src_mac and src_mac.lower() == side.mac.lower():
                return tag
        return "unknown"

    def __call__(self, agent: str, layers: dict) -> NormalizedPacket:
        ts = float(F(layers, "frame.time_epoch") or 0.0)
        if self.t0 is None:
            self.t0 = ts
        src_ip, dst_ip = F(layers, "ip.src"), F(layers, "ip.dst")
        src_mac, dst_mac = F(layers, "eth.src"), F(layers, "eth.dst")
        pkt = NormalizedPacket(
            frame=to_int(F(layers, "frame.number")) or 0,
            agent=agent,
            ts=ts,
            rel_ms=round((ts - self.t0) * 1000, 3),
            src=src_ip or src_mac or "",
            dst=dst_ip or dst_mac or "",
            length=to_int(F(layers, "frame.len")) or 0,
            info=F(layers, "_ws.col.Info") or "",
            proto=F(layers, "_ws.col.Protocol") or "OTHER",
            direction=self.direction(src_ip, src_mac),
        )
        protocols = (F(layers, "frame.protocols") or "").split(":")
        try:
            if "isakmp" in protocols or self._is_ike_port(layers):
                self._ike(pkt, layers)
            elif "esp" in protocols:
                self._esp(pkt, layers)
            elif "eapol" in protocols:
                self._eapol(pkt, layers)
            elif "macsec" in protocols or (F(layers, "eth.type") or "").lower() in ("0x88e5", "35045"):
                self._macsec(pkt, layers)
            elif "tls" in protocols:
                self._tls(pkt, layers)
            elif "ssh" in protocols:
                self._ssh(pkt, layers)
            else:
                self._generic(pkt, layers, protocols)
        except Exception as exc:  # never let one odd frame kill the live stream
            log.debug("normalize failed for frame %s: %s", pkt.frame, exc)
            pkt.tags.append("decode-error")
        if src_ip and dst_ip:
            self._mark_decap_copy(pkt, src_ip, dst_ip, ts)
        if not pkt.label:
            pkt.label = pkt.info[:80]
        return pkt

    DECAP_WINDOW_S = 0.001

    def _mark_decap_copy(self, pkt: NormalizedPacket, src: str, dst: str, ts: float) -> None:
        """A capture inside the receiving peer's netns sees every inbound ESP packet twice:
        once as ESP, then again as the cleartext inner packet that the kernel (XFRM)
        re-injects on the same interface after decrypting it - same src/dst, same
        timestamp. That copy never crossed the wire. Pair each non-ESP frame one-to-one
        with an unpaired ESP frame of the same direction within DECAP_WINDOW_S; anything
        unpaired (a real leak) keeps its tags and still counts."""
        self._esp_unpaired = [e for e in self._esp_unpaired if ts - e[2] <= self.DECAP_WINDOW_S]
        if pkt.proto == "ESP":
            self._esp_unpaired.append((src, dst, ts))
            return
        for i, (esrc, edst, _ets) in enumerate(self._esp_unpaired):
            if (esrc, edst) == (src, dst):
                del self._esp_unpaired[i]
                pkt.kind = "other"
                pkt.tags = [t for t in pkt.tags if t != "cleartext"] + ["decap-copy"]
                pkt.label = f"{pkt.proto} decrypted copy of the ESP frame before it (kernel, not on the wire)"
                return

    # ------------------------------------------------------------- IKEv2 --
    @staticmethod
    def _is_ike_port(layers: dict) -> bool:
        ports = {to_int(F(layers, "udp.srcport")), to_int(F(layers, "udp.dstport"))}
        return bool(ports & {500, 4500}) and F(layers, "esp.spi") is None

    def _ike(self, pkt: NormalizedPacket, layers: dict) -> None:
        pkt.proto, pkt.kind = "IKEv2", "handshake"
        raw = hex_bytes(F(layers, "udp.payload"))
        port = to_int(F(layers, "udp.dstport"))
        sport = to_int(F(layers, "udp.srcport"))
        if raw is not None:
            try:
                ike = ikev2.decode(ikev2.strip_non_esp_marker(raw, 4500 if 4500 in (port, sport) else None))
            except ikev2.IKEDecodeError as exc:
                pkt.tags.append("ike-decode-error")
                pkt.detail["ike_error"] = str(exc)
                return
            pkt.detail["ike"] = ike.to_dict()
            pkt.label = ike.label()
            if ike.exchange == "IKE_SA_INIT":
                if ike.is_pq_hybrid_offer():
                    pkt.tags.append("pq-kex-offer" if not ike.is_response else "pq-kex")
                elif "USE_PPK" in ike.notifies:
                    pkt.tags.append("ppk")
                else:
                    pkt.tags.append("classical-kex")
            if ike.exchange == "IKE_INTERMEDIATE":
                pkt.tags.append("pq-kex")
            if ike.fragment and ike.fragment[1] > 1:
                pkt.tags.append("fragment")
            if ike.encrypted:
                pkt.tags.append("encrypted")
            return
        # Fallback: dissector fields only
        exch = to_int(F(layers, "isakmp.exchangetype"))
        pkt.label = cp.name(cp.IKE_EXCHANGE, exch)
        pkt.detail["ike"] = {"exchange": pkt.label, "from": "tshark"}

    def _esp(self, pkt: NormalizedPacket, layers: dict) -> None:
        pkt.proto, pkt.kind = "ESP", "data"
        spi, seq = F(layers, "esp.spi"), F(layers, "esp.sequence")
        pkt.label = f"ESP spi={spi} seq={seq}"
        pkt.tags.append("encrypted")
        pkt.detail["esp"] = {"spi": spi, "sequence": to_int(seq)}

    # --------------------------------------------------------------- TLS --
    def _tls_fields(self, layers: dict) -> dict:
        hs_types = [cp.name(cp.TLS_HANDSHAKE_TYPE, to_int(x)) for x in FA(layers, "tls.handshake.type")]
        # Wireshark 4.4 reports encrypted TLS 1.3 records' outer type as opaque_type, not content_type
        content = [cp.name(cp.TLS_CONTENT_TYPE, to_int(x))
                   for x in FA(layers, "tls.record.content_type") + FA(layers, "tls.record.opaque_type")]
        groups = [cp.name(cp.TLS_GROUP, to_int(x)) for x in FA(layers, "tls.handshake.extensions_supported_group")]
        ks_groups = [cp.name(cp.TLS_GROUP, to_int(x)) for x in FA(layers, "tls.handshake.extensions_key_share_group")]
        ks_lens = [to_int(x) for x in FA(layers, "tls.handshake.extensions_key_share_key_exchange_length")]
        versions = [cp.name(cp.TLS_VERSION, to_int(x)) for x in FA(layers, "tls.handshake.extensions.supported_version")]
        legacy_ver = cp.name(cp.TLS_VERSION, to_int(F(layers, "tls.handshake.version")), "") or None
        sigs = [cp.name(cp.TLS_SIGSCHEME, to_int(x)) for x in FA(layers, "tls.handshake.sig_hash_alg")]
        cert_lens = [to_int(x) for x in FA(layers, "tls.handshake.certificate_length")]
        return {
            "handshake_types": hs_types, "content_types": content,
            "supported_groups": groups,
            "key_shares": [{"group": g, "len": ln} for g, ln in zip(ks_groups, ks_lens + [None] * len(ks_groups))],
            "supported_versions": versions, "legacy_version": legacy_ver,
            "signature_algorithms": sigs, "certificate_lengths": cert_lens,
            "cipher_suite": F(layers, "tls.handshake.ciphersuite"),
        }

    def _tls(self, pkt: NormalizedPacket, layers: dict) -> None:
        pkt.proto = "TLS"
        t = self._tls_fields(layers)
        pkt.detail["tls"] = t
        self._label_tls(pkt, t)

    def _label_tls(self, pkt: NormalizedPacket, t: dict) -> None:
        hs = t["handshake_types"]
        if hs:
            pkt.kind = "handshake"
            parts = ["/".join(hs)]
            if "ClientHello" in hs:
                shares = ", ".join(f"{k['group']}:{k['len']}B" for k in t["key_shares"])
                parts.append(f"key_share [{shares}]")
                if any(k["group"] in cp.PQ_TLS_GROUPS for k in t["key_shares"]):
                    pkt.tags.append("pq-kex-offer")
                if any(s in cp.PQ_TLS_SIGSCHEMES for s in t["signature_algorithms"]):
                    pkt.tags.append("pq-auth-offer")
            if "ServerHello" in hs:
                ver = (t["supported_versions"] or [t["legacy_version"] or "?"])[0]
                group = t["key_shares"][0]["group"] if t["key_shares"] else "none"
                parts.append(f"{ver} group {group}")
                if group in cp.PQ_TLS_GROUPS:
                    pkt.tags.append("pq-kex")
                elif ver == "TLS 1.2":
                    pkt.tags += ["classical-kex", "downgrade"]
                else:
                    pkt.tags.append("classical-kex")
            if "Certificate" in hs and t["certificate_lengths"]:
                parts.append(f"cert {t['certificate_lengths'][0]}B")
            pkt.label = " ".join(parts)
        elif "ApplicationData" in t["content_types"]:
            pkt.kind = "data"
            pkt.label = "Application Data (encrypted)"
            pkt.tags.append("encrypted")
        elif t["content_types"]:
            pkt.kind = "control"
            pkt.label = "/".join(t["content_types"])

    # --------------------------------------------------------------- SSH --
    def _ssh(self, pkt: NormalizedPacket, layers: dict) -> None:
        pkt.proto = "SSH"
        codes = [to_int(x) for x in FA(layers, "ssh.message_code")]
        names = [cp.name(cp.SSH_MSG, c) for c in codes if c is not None]
        kex = F(layers, "ssh.kex_algorithms")
        hostkeys = F(layers, "ssh.server_host_key_algorithms")
        plen = to_int(F(layers, "ssh.packet_length"))
        banner = F(layers, "ssh.protocol")
        pkt.detail["ssh"] = {"messages": names, "kex_algorithms": kex.split(",") if kex else [],
                             "host_key_algorithms": hostkeys.split(",") if hostkeys else [],
                             "packet_length": plen, "banner": banner}
        if banner:
            pkt.kind, pkt.label = "handshake", f"banner {banner}"
        elif names:
            pkt.kind = "handshake" if any(n in ("KEXINIT", "KEX_ECDH_INIT", "KEX_ECDH_REPLY", "NEWKEYS") for n in names) else "data"
            pkt.label = "/".join(names) + (f" {plen}B" if plen else "")
            if "KEXINIT" in names and kex:
                first = kex.split(",")[0]
                pkt.label += f" (first kex: {first})"
                pkt.tags.append("pq-kex-offer" if first in cp.PQ_SSH_KEX else "classical-kex")
            if "KEX_ECDH_INIT" in names or "KEX_ECDH_REPLY" in names:
                pkt.tags.append("kex-payload")
        else:
            pkt.kind, pkt.label = "data", f"encrypted packet{f' {plen}B' if plen else ''}"
            pkt.tags.append("encrypted")

    # ---------------------------------------------------- 802.1X / MACsec --
    def _eapol(self, pkt: NormalizedPacket, layers: dict) -> None:
        etype = cp.name(cp.EAPOL_TYPE, to_int(F(layers, "eapol.type")))
        pkt.proto, pkt.kind = "EAPOL", "handshake"
        parts = [etype]
        code = to_int(F(layers, "eap.code"))
        if code is not None:
            pkt.proto = "EAP"
            parts = [f"EAP-{cp.name(cp.EAP_CODE, code)}"]
            etype_id = to_int(F(layers, "eap.type"))
            if etype_id is not None:
                parts[0] += f"/{cp.name(cp.EAP_TYPE, etype_id)}"
            flags = to_int(F(layers, "eap.tls.flags"))
            if flags is not None:
                if flags & 0x20:
                    parts.append("start")
                if flags & 0x40:
                    parts.append("more-fragments")
                    pkt.tags.append("fragment")
        if etype == "EAPOL-MKA":
            pkt.proto = "MKA"
        t = self._tls_fields(layers)
        if t["handshake_types"] or t["content_types"]:
            pkt.proto = "EAP-TLS"
            pkt.detail["tls"] = t
            self._label_tls(pkt, t)
            pkt.label = " ".join(parts) + " | " + pkt.label
            pkt.kind = "handshake"
        else:
            pkt.label = " ".join(parts)
        pkt.detail["eapol"] = {"type": etype, "eap_code": code, "eap_type": to_int(F(layers, "eap.type")),
                               "eap_len": to_int(F(layers, "eap.len"))}

    def _macsec(self, pkt: NormalizedPacket, layers: dict) -> None:
        pkt.proto, pkt.kind = "MACsec", "data"
        pkt.label = f"MACsec PN={F(layers, 'macsec.PN')}"
        pkt.tags.append("encrypted")

    def _generic(self, pkt: NormalizedPacket, layers: dict, protocols: list[str]) -> None:
        if "icmp" in protocols:
            pkt.kind, pkt.proto = "data", "ICMP"
            pkt.tags.append("cleartext")
        elif "tcp" in protocols:
            pkt.kind = "control"
            pkt.proto = "TCP"
            pkt.label = f"TCP {F(layers, 'tcp.flags.str') or ''} len={F(layers, 'tcp.len')}".strip()
        elif "arp" in protocols:
            pkt.kind, pkt.proto = "control", "ARP"
