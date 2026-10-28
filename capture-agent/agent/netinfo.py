"""Find the capture interface and the management address inside a shared netns."""
from __future__ import annotations

import ipaddress
import json
import subprocess


def _addrs() -> list[dict]:
    out = subprocess.run(["ip", "-j", "-4", "addr", "show"], capture_output=True, text=True, check=True)
    return json.loads(out.stdout or "[]")


def iface_for_subnet(subnet: str) -> tuple[str, str] | None:
    """Return (ifname, ip) of the interface holding an address in `subnet`."""
    net = ipaddress.ip_network(subnet, strict=False)
    for link in _addrs():
        for a in link.get("addr_info", []):
            if a.get("family") == "inet" and ipaddress.ip_address(a["local"]) in net:
                return link["ifname"], a["local"]
    return None


def iface_exists(name: str) -> bool:
    return any(link.get("ifname") == name for link in _addrs()) or _link_exists(name)


def _link_exists(name: str) -> bool:
    # interfaces without an IPv4 address (the MACsec veth) don't show in `addr -4`
    r = subprocess.run(["ip", "link", "show", name], capture_output=True)
    return r.returncode == 0
