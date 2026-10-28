"""Build synthetic IKEv2 messages for unit tests (no captures needed)."""
from __future__ import annotations

import struct


def transform(ttype: int, tid: int, key_len: int | None = None, last: bool = False) -> bytes:
    attrs = struct.pack("!HH", 0x800E, key_len) if key_len else b""
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attrs), ttype, 0, tid) + attrs


def proposal(num: int, transforms: list[bytes], last: bool = True) -> bytes:
    body = b"".join(transforms)
    return struct.pack("!BBHBBBB", 0 if last else 2, 0, 8 + len(body), num, 1, 0, len(transforms)) + body


def payload(next_type: int, body: bytes) -> bytes:
    return struct.pack("!BBH", next_type, 0, 4 + len(body)) + body


def message(exch: int, first_payload: int, payloads: bytes, *, initiator: bool = True,
            response: bool = False, msgid: int = 0, rspi: bytes = b"\x00" * 8) -> bytes:
    flags = (0x08 if initiator else 0) | (0x20 if response else 0)
    length = 28 + len(payloads)
    hdr = struct.pack("!8s8sBBBBII", b"\x11" * 8, rspi, first_payload, 0x20, exch, flags, msgid, length)
    return hdr + payloads


def hybrid_sa_init_request() -> bytes:
    """IKE_SA_INIT req: AES-GCM-16-256 / PRF SHA2-256 / KE X25519 / ADDKE1 ML-KEM-768."""
    sa = proposal(1, [
        transform(1, 20, key_len=256),
        transform(2, 5),
        transform(4, 31),
        transform(6, 36, last=True),
    ])
    ke = struct.pack("!HH", 31, 0) + b"\xaa" * 32
    nonce = b"\xbb" * 32
    frag = struct.pack("!BBH", 0, 0, 16430)
    inter = struct.pack("!BBH", 0, 0, 16438)
    chain = (
        payload(34, sa)          # SA   -> next KE
        + payload(40, ke)        # KE   -> next Nonce
        + payload(41, nonce)     # Nonce-> next Notify
        + payload(41, frag)      # Notify FRAG -> next Notify
        + payload(0, inter)      # Notify INTERMEDIATE -> end
    )
    return message(34, 33, chain)


def classical_sa_init_response() -> bytes:
    sa = proposal(1, [transform(1, 20, key_len=256), transform(2, 5), transform(4, 31, last=True)])
    ke = struct.pack("!HH", 31, 0) + b"\xcc" * 32
    chain = payload(34, sa) + payload(40, ke) + payload(0, b"\xdd" * 32)
    return message(34, 33, chain, initiator=False, response=True, rspi=b"\x22" * 8)


def ppk_sa_init_request() -> bytes:
    sa = proposal(1, [transform(1, 20, key_len=256), transform(2, 5), transform(4, 31, last=True)])
    ke = struct.pack("!HH", 31, 0) + b"\xaa" * 32
    use_ppk = struct.pack("!BBH", 0, 0, 16435)
    chain = payload(34, sa) + payload(40, ke) + payload(41, b"\xbb" * 32) + payload(0, use_ppk)
    return message(34, 33, chain)


def intermediate_sk_response(ciphertext_len: int = 1120) -> bytes:
    """Unfragmented IKE_INTERMEDIATE response: SK payload whose first inner payload is KE."""
    return message(43, 46, payload(34, b"\xef" * ciphertext_len), initiator=False, response=True,
                   msgid=1, rspi=b"\x22" * 8)


def intermediate_fragment(num: int, total: int, ciphertext_len: int = 1100) -> bytes:
    """IKE_INTERMEDIATE request, SKF fragment carrying (encrypted) KE."""
    body = struct.pack("!HH", num, total) + b"\xee" * ciphertext_len
    return message(43, 53, payload(34 if num == 1 else 0, body), msgid=1, rspi=b"\x22" * 8)
