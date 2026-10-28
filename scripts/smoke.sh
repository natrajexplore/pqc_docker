#!/usr/bin/env bash
# End-to-end smoke test: run every scenario through the real API (via the
# frontend's nginx, which proxies /api) and require every assertion to pass.
#   ./scripts/smoke.sh                 # all scenarios whose stack is running
#   ./scripts/smoke.sh ipsec-kex-hybrid-mlkem768 tls-kex-hybrid
set -euo pipefail

BASE="${PQCW_BASE:-http://127.0.0.1:${PQCW_UI_PORT:-8080}}"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

if (( $# )); then ids=("$@")
else mapfile -t ids < <(curl -fsS "$BASE/api/scenarios" | jq -r '.[] | select(.available) | .id'); fi

pass=0; failn=0
for id in "${ids[@]}"; do
  run_id="$(curl -fsS -X POST "$BASE/api/runs" -H 'content-type: application/json' \
            -d "{\"scenario_id\":\"$id\"}" | jq -r .run_id)"
  for _ in $(seq 1 120); do
    st="$(curl -fsS "$BASE/api/runs/$run_id")"
    status="$(jq -r .status <<<"$st")"
    [[ "$status" == completed || "$status" == failed || "$status" == aborted ]] && break
    sleep 1
  done
  failed_asserts="$(jq -r '[.assertions[] | select(.passed|not) | .id] | join(",")' <<<"$st")"
  if [[ "$status" == completed && -z "$failed_asserts" ]]; then
    printf '  \033[32mPASS\033[0m %-40s %s\n' "$id" "$(jq -r '.verdict.summary // ""' <<<"$st")"; ((pass++))
  else
    printf '  \033[31mFAIL\033[0m %-40s status=%s failed=[%s]\n' "$id" "$status" "$failed_asserts"; ((failn++))
  fi
done
echo; echo "passed=$pass failed=$failn"
(( failn == 0 ))
