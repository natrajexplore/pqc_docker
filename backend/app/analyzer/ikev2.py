"""Minimal, dependency-free IKEv2 decoder.

Why our own instead of trusting the tshark dissector: the bits that prove a
post-quantum handshake (RFC 9370 Additional Key Exchange transforms, ML-KEM
method IDs, RFC 9242 IKE_INTERMEDIATE, RFC 8784 PPK notifies) are recent, and
the dissector shipped with a given distro may print them as "Unknown". The
plaintext parts of IKE are simple enough to decode exactly:

  * IKE_SA_INIT is unencrypted -> full SA proposal / KE / Notify decode.
  * everything after it is inside SK (46) or SKF (53) -> we report sizes,
    fragment numbers and the first inner payload type, which is enough to tell
    an IKE_INTERMEDIATE carrying ML-KEM from an IKE_AUTH carrying certificates.

Input is the UDP payload (port 500) or the UDP payload after the 4-byte non-ESP
marker (port 4500).
"""
from __future__ import annotations

import struct
from dataclasses import asdict, dataclass, field

from . import codepoints as cp

IKE_HEADER_LEN = 28
FLAG_INITIATOR = 0x08
FLAG_RESPONSE = 0x20


class IKEDecodeError(ValueError):
    pass


@dataclass
class Transform:
    type: str
    id: int
    name: str
    key_length: int | None = None


@dataclass
class Proposal:
    number: int
    protocol: int
    transforms: list[Transform] = field(default_factory=list)

    def by_type(self, ttype: str) -> list[Transform]:
        return [t for t in self.transforms if t.type == ttype]


@dataclass
class Payload:
    type: str
    type_id: int
    length: int
    # decoded detail, shape depends on type
    detail: dict = field(default_factory=dict)


@dataclass
class IKEMessage:
    ispi: str
    rspi: str
    exchange: str
    exchange_id: int
    is_initiator: bool
    is_response: bool
    message_id: int
    length: int
    payloads: list[Payload] = field(default_factory=list)
    proposals: list[Proposal] = field(default_factory=list)
    notifies: list[str] = field(default_factory=list)
    ke_method: str | None = None
    ke_data_len: int | None = None
    encrypted: bool = False
    fragment: tuple[int, int] | None = None     # (number, total) for SKF
    inner_first_payload: str | None = None      # first payload inside SK/SKF

    # ------------------------------------------------------------- helpers --
    @property
    def role(self) -> str:
        return "response" if self.is_response else "request"

    def offered_ke(self) -> list[str]:
        out: list[str] = []
        for p in self.proposals:
            out += [t.name for t in p.by_type("KE")]
        return out

    def offered_additional_ke(self) -> dict[str, list[str]]:
        """{'ADDKE1': ['ML_KEM_768'], ...} across all proposals."""
        out: dict[str, list[str]] = {}
        for p in self.proposals:
            for t in p.transforms:
                if t.type.startswith("ADDKE") and t.name != "NONE":
                    out.setdefault(t.type, [])
                    if t.name not in out[t.type]:
                        out[t.type].append(t.name)
        return out

    def is_pq_hybrid_offer(self) -> bool:
        return any(m in cp.PQ_KE_METHODS for ms in self.offered_additional_ke().values() for m in ms) \
            or any(m in cp.PQ_KE_METHODS for m in self.offered_ke())

    def label(self) -> str:
        """Short human label for the ladder diagram."""
        parts = [self.exchange, "resp" if self.is_response else "req"]
        if self.fragment:
            parts.append(f"frag {self.fragment[0]}/{self.fragment[1]}")
        if self.exchange == "IKE_SA_INIT":
            ke = self.ke_method or ",".join(self.offered_ke()) or "?"
            parts.append(f"KE {ke}")
            add = self.offered_additional_ke()
            if add:
                parts.append("+ " + " ".join(f"{k}:{'/'.join(v)}" for k, v in add.items()))
            if "USE_PPK" in self.notifies:
                parts.append("USE_PPK")
        return " ".join(parts)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["offered_additional_ke"] = self.offered_additional_ke()
        d["label"] = self.label()
        return d


# ---------------------------------------------------------------- decode --
def strip_non_esp_marker(payload: bytes, udp_port: int | None) -> bytes:
    if udp_port == 4500:
        if len(payload) >= 4 and payload[:4] == b"\x00\x00\x00\x00":
            return payload[4:]
        raise IKEDecodeError("UDP/4500 packet without non-ESP marker (this is UDP-encapsulated ESP)")
    return payload


def decode(payload: bytes) -> IKEMessage:
    if len(payload) < IKE_HEADER_LEN:
        raise IKEDecodeError("shorter than an IKE header")
    ispi, rspi, np_, ver, exch, flags, msgid, length = struct.unpack("!8s8sBBBBII", payload[:IKE_HEADER_LEN])
    if ver >> 4 != 2:
        raise IKEDecodeError(f"not IKEv2 (version byte 0x{ver:02x})")
    if length > len(payload):
        raise IKEDecodeError(f"truncated: header says {length} bytes, have {len(payload)}")

    msg = IKEMessage(
        ispi=ispi.hex(), rspi=rspi.hex(),
        exchange=cp.name(cp.IKE_EXCHANGE, exch), exchange_id=exch,
        is_initiator=bool(flags & FLAG_INITIATOR), is_response=bool(flags & FLAG_RESPONSE),
        message_id=msgid, length=length,
    )

    off = IKE_HEADER_LEN
    next_type = np_
    data = payload[:length]
    while next_type != 0 and off + 4 <= len(data):
        this_type = next_type
        next_type, _crit, plen = struct.unpack("!BBH", data[off:off + 4])
        if plen < 4 or off + plen > len(data):
            raise IKEDecodeError(f"bad payload length {plen} at offset {off}")
        body = data[off + 4: off + plen]
        p = Payload(type=cp.name(cp.IKE_PAYLOAD, this_type), type_id=this_type, length=plen)
        try:
            _decode_payload(msg, p, body, inner_next=next_type)
        except struct.error as exc:  # payload body shorter than its fixed fields (imported pcaps are untrusted)
            raise IKEDecodeError(f"truncated {p.type} payload at offset {off}") from exc
        msg.payloads.append(p)
        off += plen
        if this_type in (46, 53):  # SK / SKF: everything else is ciphertext
            break
    return msg


def _decode_payload(msg: IKEMessage, p: Payload, body: bytes, inner_next: int) -> None:
    t = p.type_id
    if t == 33:  # SA
        msg.proposals = _decode_sa(body)
        p.detail = {"proposals": [asdict(pr) for pr in msg.proposals]}
    elif t == 34:  # KE
        group, _res = struct.unpack("!HH", body[:4])
        msg.ke_method = cp.name(cp.IKE_KE_METHOD, group)
        msg.ke_data_len = len(body) - 4
        p.detail = {"method": msg.ke_method, "method_id": group, "data_len": msg.ke_data_len}
    elif t == 41:  # Notify
        _proto, spi_size, ntype = struct.unpack("!BBH", body[:4])
        nname = cp.name(cp.IKE_NOTIFY, ntype)
        msg.notifies.append(nname)
        p.detail = {"notify": nname, "notify_id": ntype, "data_len": len(body) - 4 - spi_size}
    elif t == 46:  # SK
        msg.encrypted = True
        msg.inner_first_payload = cp.name(cp.IKE_PAYLOAD, inner_next)
        p.detail = {"inner_first_payload": msg.inner_first_payload, "ciphertext_len": len(body)}
    elif t == 53:  # SKF (RFC 7383)
        num, total = struct.unpack("!HH", body[:4])
        msg.encrypted = True
        msg.fragment = (num, total)
        # the Next Payload field is only meaningful in fragment number 1
        msg.inner_first_payload = cp.name(cp.IKE_PAYLOAD, inner_next) if num == 1 else None
        p.detail = {"fragment_number": num, "total_fragments": total, "ciphertext_len": len(body) - 4,
                    "inner_first_payload": msg.inner_first_payload}
    elif t == 40:
        p.detail = {"nonce_len": len(body)}


def _decode_sa(body: bytes) -> list[Proposal]:
    proposals: list[Proposal] = []
    off = 0
    while off + 8 <= len(body):
        last, _r, plen, pnum, proto, spi_size, ntrans = struct.unpack("!BBHBBBB", body[off:off + 8])
        if plen < 8 or off + plen > len(body):
            raise IKEDecodeError("bad proposal length")
        prop = Proposal(number=pnum, protocol=proto)
        toff = off + 8 + spi_size
        end = off + plen
        for _ in range(ntrans):
            if toff + 8 > end:
                break
            _tlast, _tr, tlen, ttype, _tr2, tid = struct.unpack("!BBHBBH", body[toff:toff + 8])
            key_len = None
            attrs = body[toff + 8: toff + tlen]
            if len(attrs) >= 4:
                atype, aval = struct.unpack("!HH", attrs[:4])
                if atype == 0x800E:  # TV-format Key Length attribute
                    key_len = aval
            tname = cp.IKE_TRANSFORM_TYPE.get(ttype, f"T{ttype}")
            prop.transforms.append(Transform(type=tname, id=tid, name=_transform_name(tname, tid), key_length=key_len))
            toff += tlen
        proposals.append(prop)
        off += plen
        if last == 0:
            break
    return proposals


def _transform_name(ttype: str, tid: int) -> str:
    if ttype == "KE" or ttype.startswith("ADDKE"):
        return cp.name(cp.IKE_KE_METHOD, tid)
    if ttype == "ENCR":
        return cp.name(cp.IKE_ENCR, tid)
    if ttype == "PRF":
        return cp.name(cp.IKE_PRF, tid)
    if ttype == "INTEG":
        return cp.name(cp.IKE_INTEG, tid)
    return str(tid)
