---
description: Draft, validate and calibrate a new scenario from a one-line idea
argument-hint: <idea, e.g. "TLS with SecP256r1MLKEM768">
---

New scenario idea: $ARGUMENTS

1. Read `docs/SCENARIOS.md` (schema, assertion kinds) and copy the closest existing
   file in `scenarios/` as a starting point. Keep one idea per scenario and put it in
   the same `group` as the baseline it should be compared with.
2. Draft the YAML: narration on the steps a presenter would talk over; wire assertions
   first; endpoint assertions (`auth-*`) only as corroboration; loose thresholds for now.
3. Validate offline: `cd backend && python -c "from pathlib import Path; from app.scenarios import ScenarioStore as S; s=S(Path('../scenarios')); s.load(); print(s.errors)"`.
4. If the stack is up: `POST /api/scenarios/reload`, run it with `/run-scenario`, then
   tighten thresholds and regexes to the observed values and fill `expected_numbers`.
5. Add the row to the catalogue table in `docs/SCENARIOS.md`.
