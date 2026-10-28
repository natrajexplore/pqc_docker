---
description: Run one scenario through the live API and triage every failed step or assertion
argument-hint: <scenario-id>
---

Run scenario `$ARGUMENTS` end to end and explain the result.

1. `curl -s 127.0.0.1:${PQCW_UI_PORT:-8080}/api/scenarios | jq '.[] | select(.id=="$ARGUMENTS")'`
   - if `available` is false, show `missing` and the `make up PROFILES=...` command, then stop.
2. Start it: `POST /api/runs {"scenario_id": "$ARGUMENTS"}`; poll `GET /api/runs/<id>` until
   status is completed, failed or aborted.
3. Report the verdict summary, the metrics (handshake bytes, frames, flights, fragments) and
   every assertion with pass/fail and message.
4. For each failure decide which is wrong - the code, the threshold, or the regex - using
   the step outputs and, if needed, `tshark -r` on the pcap inside the backend container
   (`docker compose exec backend tshark -r /captures/<id>/<agent>.pcapng -V`).
   Do not loosen an assertion just to make it pass: show the evidence first.
5. Propose the fix as a diff; apply it only if I say so, then re-run once to confirm.
