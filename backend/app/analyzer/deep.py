"""Offline tshark work on finished pcaps: packet detail trees, imports, TLS decryption.

All tshark invocations use argv lists (no shell) and read only files under the
captures directory.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from .fields import LIVE_FIELDS

log = logging.getLogger(__name__)

# X.509 AlgorithmIdentifier OIDs -> names (signature + SubjectPublicKeyInfo)
OID_NAMES = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.3.101.112": "Ed25519",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
}
PQ_OIDS = {k for k, v in OID_NAMES.items() if v.startswith("ML-DSA")}


async def _tshark(*args: str, timeout: float = 30) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec("tshark", *args, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        raise
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


def _keylog_opts(keylog: Path | None) -> list[str]:
    return ["-o", f"tls.keylog_file:{keylog}"] if keylog and keylog.exists() else []


async def packet_detail(pcap: Path, frame: int, keylog: Path | None = None) -> dict:
    """Full dissection tree + raw hex for one frame (the UI's detail pane)."""
    rc, out, err = await _tshark("-r", str(pcap), *_keylog_opts(keylog), "-Y", f"frame.number == {int(frame)}",
                                 "-T", "json", "-x", "--no-duplicate-keys")
    if rc != 0:
        raise RuntimeError(err.strip() or f"tshark exited {rc}")
    docs = json.loads(out or "[]")
    if not docs:
        raise LookupError(f"frame {frame} not in {pcap.name}")
    layers = docs[0].get("_source", {}).get("layers", {})
    raw_hex = ""
    if "frame_raw" in layers:
        fr = layers.pop("frame_raw")
        raw_hex = fr[0] if isinstance(fr, list) else str(fr)
    # drop the *_raw companions from the tree; the hex pane covers them
    tree = _strip_raw(layers)
    return {"frame": frame, "tree": tree, "hex": raw_hex, "decrypted": bool(_keylog_opts(keylog))}


def _strip_raw(node):
    if isinstance(node, dict):
        return {k: _strip_raw(v) for k, v in node.items() if not k.endswith("_raw")}
    if isinstance(node, list):
        return [_strip_raw(v) for v in node]
    return node


async def ek_from_file(pcap: Path, keylog: Path | None = None) -> list[dict]:
    """Decode a whole pcap with the same fields the live agents use (imports, re-analysis)."""
    field_args: list[str] = []
    for f in LIVE_FIELDS:
        field_args += ["-e", f]
    rc, out, err = await _tshark("-r", str(pcap), *_keylog_opts(keylog), "-T", "ek", *field_args, timeout=120)
    if rc != 0 and "aren't valid" in err:
        # older Wireshark: retry without the fields it rejects
        bad = {line.strip() for line in err.splitlines() if line.startswith(("\t", " "))}
        field_args = []
        for f in LIVE_FIELDS:
            if f not in bad:
                field_args += ["-e", f]
        rc, out, err = await _tshark("-r", str(pcap), *_keylog_opts(keylog), "-T", "ek", *field_args, timeout=120)
    if rc != 0:
        raise RuntimeError(err.strip() or f"tshark exited {rc}")
    docs = []
    for line in out.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "layers" in d:
            docs.append(d["layers"])
    return docs


async def tls_certificate_evidence(pcap: Path, keylog: Path | None) -> dict:
    """With a lab key log, TLS 1.3's encrypted Certificate message becomes readable:
    report the certificate signature / key algorithms actually sent on the wire."""
    if not keylog or not keylog.exists():
        return {}
    rc, out, err = await _tshark("-r", str(pcap), *_keylog_opts(keylog), "-Y", "tls.handshake.type == 11",
                                 "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|",
                                 "-e", "frame.number", "-e", "tls.handshake.certificate_length",
                                 "-e", "x509af.algorithm.id")
    if rc != 0:
        log.warning("TLS decrypt evidence failed: %s", err.strip())
        return {}
    certs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        oids = [o for o in parts[2].split("|") if o]
        certs.append({
            "frame": int(parts[0]),
            "certificate_lengths": [int(x) for x in parts[1].split("|") if x.isdigit()],
            "algorithms": [OID_NAMES.get(o, o) for o in oids],
            "post_quantum": any(o in PQ_OIDS for o in oids),
        })
    return {"decrypted_with_keylog": True, "certificate_messages": certs}
