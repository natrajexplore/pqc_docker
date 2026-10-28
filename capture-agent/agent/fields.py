"""tshark fields streamed live to the backend.

tshark aborts the whole capture if a single `-e` field is unknown to its
Wireshark version, so the agent intersects this list with `tshark -G fields` at
start-up and logs whatever it had to drop. Keep the list protocol-grouped; the
backend's analyzer/normalize.py maps the EK names (dots -> underscores) back.
"""
from __future__ import annotations

import logging
import subprocess

log = logging.getLogger("agent.fields")

LIVE_FIELDS: list[str] = [
    # frame / L2 / L3 / L4
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    "_ws.col.Protocol", "_ws.col.Info",
    "eth.src", "eth.dst", "eth.type",
    "ip.src", "ip.dst", "ip.proto",
    "udp.srcport", "udp.dstport", "udp.length", "udp.payload",
    "tcp.srcport", "tcp.dstport", "tcp.len", "tcp.flags.str",
    # IKEv2 (we also decode udp.payload ourselves - see backend analyzer/ikev2.py)
    "isakmp.ispi", "isakmp.rspi", "isakmp.exchangetype", "isakmp.flags",
    "isakmp.messageid", "isakmp.length", "isakmp.nextpayload",
    # ESP data plane
    "esp.spi", "esp.sequence",
    # TLS 1.3 (also inside EAP-TLS)
    "tls.record.content_type", "tls.record.length", "tls.handshake.type",
    "tls.handshake.length", "tls.handshake.version", "tls.handshake.extensions.supported_version",
    "tls.handshake.extensions_supported_group",
    "tls.handshake.extensions_key_share_group",
    "tls.handshake.extensions_key_share_key_exchange_length",
    "tls.handshake.ciphersuite", "tls.handshake.sig_hash_alg",
    "tls.handshake.certificate_length",
    # SSH
    "ssh.protocol", "ssh.message_code", "ssh.packet_length",
    "ssh.kex_algorithms", "ssh.server_host_key_algorithms",
    # 802.1X / EAP / MKA / MACsec
    "eapol.version", "eapol.type", "eapol.len",
    "eap.code", "eap.id", "eap.type", "eap.len", "eap.tls.flags", "eap.tls.len",
    "macsec.SL", "macsec.PN",
]


def available_fields() -> set[str]:
    out = subprocess.run(["tshark", "-G", "fields"], capture_output=True, text=True)
    names: set[str] = set()
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) > 2 and parts[0] in ("F", "P"):
            names.add(parts[2])
    # _ws.col.* are virtual column fields and do not appear in -G fields
    names.update(f for f in LIVE_FIELDS if f.startswith("_ws.col."))
    return names


def usable_live_fields() -> list[str]:
    have = available_fields()
    usable = [f for f in LIVE_FIELDS if f in have]
    dropped = sorted(set(LIVE_FIELDS) - set(usable))
    if dropped:
        log.warning("tshark does not know %d field(s), dropped: %s", len(dropped), ", ".join(dropped))
    return usable
