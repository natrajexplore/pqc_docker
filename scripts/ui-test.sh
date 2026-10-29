#!/usr/bin/env bash
# End-to-end UI test: frontend/e2e/ui.test.mjs in a throwaway headless-Chromium
# container on the mgmt network, against the running lab. Needs mgmt + `tls` up.
# Screenshots, the exported SVG and results.json land in frontend/e2e/out/.
#   ./scripts/ui-test.sh            # or: make test-ui
set -euo pipefail
cd "$(dirname "$0")/.."

PW_VERSION=1.48.0                     # the npm package must match the image's browsers
IMAGE="mcr.microsoft.com/playwright:v${PW_VERSION}-noble"
OUT=frontend/e2e/out

ip="$(docker inspect -f '{{(index .NetworkSettings.Networks "pqcw_mgmt").IPAddress}}' pqcw-frontend 2>/dev/null || true)"
[[ -n "$ip" ]] || { echo "pqcw-frontend is not running - start the lab first (make up PROFILES=\"tls\")" >&2; exit 2; }

mkdir -p "$OUT"
rm -f "$OUT"/*
host_path() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
user_args=()
[[ "$(uname -s)" == Linux ]] && user_args=(--user "$(id -u):$(id -g)" -e HOME=/tmp)

# Git Bash would rewrite the container-side paths below; MSYS_NO_PATHCONV stops it.
MSYS_NO_PATHCONV=1 docker run --rm --network pqcw_mgmt --ipc=host "${user_args[@]}" \
  -e PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 -e FRONTEND_IP="$ip" -e OUT_DIR=/out \
  -v "$(host_path "$PWD/frontend/e2e/ui.test.mjs"):/e2e/ui.test.mjs:ro" \
  -v "$(host_path "$PWD/$OUT"):/out" \
  "$IMAGE" sh -c "mkdir -p /tmp/app && cp /e2e/ui.test.mjs /tmp/app/ && cd /tmp/app \
    && npm init -y >/dev/null && npm i --no-audit --no-fund playwright@${PW_VERSION} >/dev/null 2>&1 \
    && node ui.test.mjs"
