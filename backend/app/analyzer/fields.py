"""Field list for offline decoding (imports, re-analysis).

GENERATED COPY of capture-agent/agent/fields.py LIVE_FIELDS - the agent is the
source of truth. tests/test_fields_sync.py fails if the two drift apart.
"""
from __future__ import annotations

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
