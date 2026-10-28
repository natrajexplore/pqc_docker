---
description: Pick up the first unchecked item in docs/IMPLEMENTATION_PLAN.md and complete it
---

1. Read `docs/IMPLEMENTATION_PLAN.md` and find the first phase with unchecked boxes.
   Tell me in one sentence which item you are taking.
2. Re-read the parts of `CLAUDE.md` that apply (ground rules always).
3. Do the item. Prefer the Makefile targets. If it needs Docker and Docker is not
   reachable, say so and do the offline part (tests, fixtures, docs) instead.
4. Verify it: `make test` at minimum; for runtime items, run the relevant scenario
   through the API (`/run-scenario`) and read every assertion result.
5. Tick the box in the plan, and if you learned a real number (bytes, frames,
   fragments), write it into that scenario's `expected_numbers`.
6. Summarise: what changed, what you verified, what's next. Stop after one item
   unless I said "keep going".

$ARGUMENTS
