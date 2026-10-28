# CLAUDE.md - PQC WireScope

You are working on **PQC WireScope**: a Docker lab that runs post-quantum
handshakes (ML-KEM key exchange, ML-DSA authentication) across **IPsec/IKEv2,
TLS 1.3, SSH and MACsec/802.1X**, captures every packet end to end, and shows
the capture live in a web UI with a two-pillar PQC verdict.

It builds on **juliogomez/pqc** (vendored as a git submodule at
`vendor/juliogomez-pqc`, MIT). We build its Dockerfiles unmodified and add the
automation, capture and UI layers on top. Read `docs/ARCHITECTURE.md` before
changing anything structural, and `docs/IMPLEMENTATION_PLAN.md` to see which
phase we are in.

## Ground rules

1. **Never fork the upstream Dockerfiles.** If a lab image needs something, wrap
   it (entrypoint wrapper, mounted script, extra sidecar) or open an upstream PR.
   Our compose files point `build.context` at `vendor/juliogomez-pqc/learn/docker`.
2. **The wire is the source of truth.** A verdict is "wire" evidence only if it was
   decoded from cleartext handshake bytes (or a lab-key-log decryption). Endpoint
   logs are "endpoint" evidence. Scenario declarations are "declared". Never
   upgrade evidence strength in code or copy.
3. **Address peers by lab IP, never by service name.** Every node is dual-homed
   (lab network + `pqcw_mgmt`). Docker DNS may return the mgmt address and the
   handshake would bypass the capture interface.
4. **No secrets in git.** PSKs, PPKs and the agent token come from `.env`
   (`make secrets`). Certificates and keys are minted at run time into named
   Docker volumes (`pqcw_*_pki`, `pqcw_ssh_keys`), never into the working tree.
5. **Least privilege stays.** No `privileged: true`. The backend reaches Docker
   only through `socket-proxy` (containers + exec only). Capture agents bind their
   API to the mgmt leg only and require `X-PQCW-Token`. Don't widen any of this
   without writing down why in `docs/SECURITY.md`.
6. **Tests before claims.** `make test` must pass. When you add a protocol decoder
   or assertion kind, add a unit test with synthetic bytes (see
   `backend/tests/ike_builder.py`) and, once you have a real capture, a golden
   fixture under `backend/tests/fixtures/`.
7. **Codepoints live in two places**: `backend/app/analyzer/codepoints.py` and
   `docs/PQC_WIRE_REFERENCE.md`. Change both or neither. Several are marked
   `verify:` - check them against the IANA registries before relying on them.
8. **The live field list has one source**: `capture-agent/agent/fields.py`.
   `backend/app/analyzer/fields.py` is a generated copy; `test_fields_sync.py`
   fails if they drift.

## Layout

```
compose.yaml                 root project (name: pqcw) - include: of every stack
stacks/<stack>/compose.yaml  one per profile: mgmt, ipsec, ipsec-auth, tls, ssh, macsec
stacks/<stack>/config/       protocol configs (swanctl variants, sshd, hostapd, wpa)
stacks/*/*.sh                credential + wrapper scripts mounted into upstream images
capture-agent/               sidecar: dumpcap -> pcapng, tshark -> live EK JSON stream
backend/app/                 FastAPI: scenarios, orchestrator, docker exec, analyzer
backend/app/analyzer/        ikev2.py (own decoder), normalize.py, verdict.py, deep.py
scenarios/*.yaml             declarative runs: steps, capture filter, assertions
frontend/src/                React + Vite: rail, verdict strip, ladder, packets, steps
scripts/                     bootstrap, secrets, preflight, smoke, dev mock server
docs/                        architecture, plan, learning path, scenarios, wire reference
vendor/juliogomez-pqc/       upstream labs (submodule) - read-only for us
```

## Commands

```bash
make bootstrap          # submodule + .env secrets (first time)
make preflight          # what will work on this Docker host (XFRM, MACsec, subnets)
make up                 # all stacks; PROFILES="ipsec tls" for a subset
make test               # backend pytest + frontend typecheck/build (no Docker needed)
make lint               # ruff, shellcheck, tsc
make smoke              # every available scenario through the real API
make logs               # backend + agent logs
make down / make nuke   # stop / stop and delete PKI, captures, mgmt network
```

No-Docker development loop for UI and analyzer work:
```bash
cd frontend && npm run build && cd ../scripts
python -m uvicorn dev_mock_server:app --port 8765   # real API, fake docker + agent
```

## How a run works (keep this mental model)

`POST /api/runs` -> `Orchestrator.start` takes the stack lock -> executes the
scenario's steps in order (`exec` via socket-proxy, `wait_for`, `resolve` into
`${vars}`, `capture_start`/`capture_stop` against the stack's agent) -> every
agent packet is normalized and pushed to `/ws/runs/{id}` as it arrives ->
cleanup steps always run -> `compute_metrics` -> assertions -> two-pillar
verdict -> `run.json` persisted next to the pcapng in the `pqcw_captures` volume.

## Adding a scenario

1. Copy the closest file in `scenarios/`; file name must equal `id`.
2. Steps reference logical node names from `nodes:`; non-detached commands are
   wrapped in `timeout` automatically - set `timeout:` per exec if needed.
3. Daemons (`hostapd`, `sshd`, `s_server`) start with `detach: true` and must log
   to a file; follow with a `wait_for` that greps that file or `ss -ltn`.
4. Assertions: prefer wire kinds (`ikev2.*`, `tls.*`, `ssh.*`, `eap.frames`,
   `count`). Name endpoint-evidence auth checks `auth-*` so the verdict credits them.
5. `POST /api/scenarios/reload`, run it, then calibrate numeric thresholds from
   the real capture and record the observed numbers in `expected_numbers`.

## Adding an assertion kind

Register it in `backend/app/analyzer/verdict.py` with `@assertion("kind")`,
read only from `Metrics.protocol`, packets or step outputs, add a test, and
document it in `docs/SCENARIOS.md`.

## Style

- Python 3.11+, ruff config in `backend/pyproject.toml`, type hints everywhere,
  pydantic models at every boundary. Never `shell=True`; tshark/dumpcap get argv lists.
- Shell: `set -euo pipefail` (bash) / `set -eu` (sh), quote everything, shellcheck clean.
- TypeScript strict; types in `frontend/src/types.ts` mirror backend models.
- UI copy: sentence case, plain verbs, say what happened and what to do next. The
  ladder is the visual hero - keep the rest quiet (see `docs/ARCHITECTURE.md#ui`).

## Known unknowns (check, don't assume)

- Exact `swanctl --list-sas` / `pki --print` wording for ML-DSA on the strongSwan
  `ml-dsa` branch - scenario regexes are deliberately loose; tighten after phase 3.
- Composite SSH algorithm name - `ssh-auth-composite` discovers it with `ssh -Q`.
- IKE_AUTH fragment counts for ML-DSA in containers - thresholds are estimates.
- `tecnativa/docker-socket-proxy` tag - confirm and pin by digest in phase 1.
- tshark field names vary by Wireshark version - the agent drops unknown fields
  at start-up and logs them; check `make logs` after the first `make up`.
