#!/usr/bin/env bash
# Preflight: tell the user, before a 20-minute build, what will and will not work
# on this Docker host. Exit non-zero only for hard blockers.
set -uo pipefail

ok()   { printf '  \033[32m[ok]\033[0m   %s\n' "$*"; }
warn() { printf '  \033[33m[warn]\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m[fail]\033[0m %s\n' "$*"; FAILED=1; }
FAILED=0
PROBE_IMG=alpine:3.20

echo "PQC WireScope preflight"

command -v docker >/dev/null && ok "docker CLI: $(docker --version)" || fail "docker CLI not found"
if docker info >/dev/null 2>&1; then ok "docker daemon reachable"; else fail "docker daemon not reachable"; fi

cv="$(docker compose version --short 2>/dev/null || true)"
if [[ -z "$cv" ]]; then fail "docker compose v2 plugin not found"
else
  major=${cv%%.*}; rest=${cv#*.}; minor=${rest%%.*}
  if (( major > 2 || (major == 2 && minor >= 20) )); then ok "compose $cv (include: supported)"
  else fail "compose $cv is too old - need >= 2.20 for 'include:'"; fi
fi

[[ -f vendor/juliogomez-pqc/learn/docker/Dockerfile ]] && ok "upstream labs present" || warn "upstream labs missing - run 'make bootstrap'"
[[ -f .env ]] && ok ".env present" || warn ".env missing - run 'make secrets'"

# Kernel features, probed from a throwaway container with only NET_ADMIN.
# busybox `ip` has no xfrm/macsec support, so install real iproute2 first.
probe() { docker run --rm --cap-add NET_ADMIN "$PROBE_IMG" sh -c "apk add -q iproute2 >/dev/null 2>&1 && $1" >/dev/null 2>&1; }
docker image inspect "$PROBE_IMG" >/dev/null 2>&1 || docker pull -q "$PROBE_IMG" >/dev/null 2>&1

if probe 'ip xfrm state list'; then ok "kernel XFRM available (IPsec ESP data plane)"
else warn "kernel XFRM not usable - IKE handshakes still capture, ESP data plane will not come up"; fi

if probe 'ip link add d0 type dummy && ip link add link d0 m0 type macsec'; then
  ok "kernel MACsec available (optional encrypted 0x88e5 data plane)"
else
  warn "kernel MACsec NOT available (normal on Docker Desktop) - EAP-TLS handshake scenarios still work"
fi

# Subnet collisions with existing Docker networks.
for net in 172.29.0.0/24 172.30.0.0/24 172.31.0.0/24 172.32.0.0/24 172.33.0.0/24 172.34.0.0/24 172.35.0.0/29; do
  owner="$(docker network ls -q | xargs -r docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | grep -F " $net" | awk '{print $1}' | head -1)"
  if [[ -n "$owner" && "$owner" != pqcw_* ]]; then fail "subnet $net already used by network '$owner'"
  fi
done
ok "subnet check done"

mem_bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
if (( mem_bytes > 0 && mem_bytes < 4000000000 )); then warn "Docker has < 4 GB RAM; parallel source builds may be slow"; fi

echo
(( FAILED )) && { echo "Preflight found blockers."; exit 1; } || echo "Preflight passed."
