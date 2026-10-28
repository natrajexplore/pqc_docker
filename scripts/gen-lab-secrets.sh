#!/usr/bin/env bash
# Generate LAB-ONLY secrets into .env. Upstream labs commit a throwaway PSK;
# here every secret is random per checkout and stays out of git.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v openssl >/dev/null || { echo "openssl is required on the host" >&2; exit 1; }

[[ -f .env ]] || cp .env.example .env

psk="$(openssl rand -base64 33 | tr -d '/+=\n' | cut -c1-40)"
ppk="$(openssl rand -hex 32)"   # 256-bit RFC 8784 PPK
agent_token="$(openssl rand -hex 24)"   # backend <-> capture-agent shared token

set_kv() {
  local key="$1" val="$2"
  if grep -q "^${key}=" .env; then
    # portable in-place edit (GNU and BSD sed)
    sed -i.bak "s|^${key}=.*|${key}=${val}|" .env && rm -f .env.bak
  else
    echo "${key}=${val}" >> .env
  fi
}

set_kv PQCW_IKE_PSK "$psk"
set_kv PQCW_IKE_PPK_HEX "$ppk"
set_kv PQCW_AGENT_TOKEN "$agent_token"
chmod 600 .env
echo ">> Wrote fresh lab secrets to .env (mode 600). Restart IPsec nodes to pick them up."
