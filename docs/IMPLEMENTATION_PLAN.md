# Implementation plan

The scaffold is complete: every file exists, the analyzer and orchestrator are
covered by 17 offline tests, all 18 scenarios validate against the schema, and
the UI builds and has been checked against a mock backend. What has **not**
happened yet is a run against real containers. These phases take it there.
Work them in order; each ends with something you can demo.

Use `/next-phase` in Claude Code to pick up where the checklist stops.

---

## Phase 0 - Learn the material by hand (half a day)

Goal: understand what the automation will do before automating it.

- [ ] Run upstream `learn/ipsec/key-exchange` by hand, exactly as its README says.
- [ ] Watch the DevNet Ep. 120 stream sections on the container labs.
- [ ] Read `docs/LEARNING_PATH.md` weeks 1-2.

Done when: you can explain why IKEv2 needs IKE_INTERMEDIATE for ML-KEM and TLS doesn't.

## Phase 1 - Bring the stacks up (day 1)

- [x] `make bootstrap`, then pin the submodule to the commit you tested:
      `git -C vendor/juliogomez-pqc rev-parse HEAD` -> note it in `NOTICE.md`.
- [x] `make preflight`; record which features your host has.
- [x] Confirm the `tecnativa/docker-socket-proxy` tag exists; pin it by digest.
- [x] `make up PROFILES=ipsec` (the first build compiles strongSwan: 5-10 min).
- [x] `docker compose ps` shows initiator, responder, cap-ipsec healthy.
- [x] `make logs`: the agent lists any tshark fields it dropped. Remove or rename
      them in `capture-agent/agent/fields.py`, then regenerate the backend copy.
- [x] Capture volume permissions: if the backend logs "could not persist run",
      check that the agent's chmod on `/captures` worked (rootless Docker may need
      `docker run --rm -v pqcw_captures:/c alpine chmod 1777 /c`).

Done when: `curl 127.0.0.1:8080/api/scenarios` shows the four IPsec key-exchange
scenarios with `"available": true`.

## Phase 2 - First real run: IPsec key exchange (day 2)

- [x] Run `ipsec-kex-classical` and `ipsec-kex-hybrid-mlkem768` from the UI.
- [x] Verify swanctl variant switching works on both peers (step "load").
- [x] Compare ladder bytes with upstream Part 4 (IKE_INTERMEDIATE ~1250 B in two
      fragments, response ~1155 B). Write the observed values into the scenario's
      `expected_numbers`.
- [x] Save both pcaps as golden fixtures in `backend/tests/fixtures/` and add
      `test_fixtures.py` replaying them through `tshark -T ek` -> normalizer ->
      verdict (skip the test when tshark is absent).
- [x] Run `ipsec-kex-ppk` and `ipsec-kex-hybrid-mlkem1024`.
- [x] Build `pqcw/strongswan:ml-dsa` (`make up PROFILES=ipsec-auth`). Pinning to a commit is
      not possible without forking upstream (`git clone --branch` rejects hashes); the
      known-good commit is recorded in `.env.example` instead.

Done when: `make smoke` passes for the `ipsec` stack and the compare view shows the
classical-vs-hybrid byte ratio.

## Phase 3 - Calibrate every scenario (days 3-4)

For each stack (`ipsec-auth`, `tls`, `ssh`, `macsec`):

- [ ] Run each scenario, read every failed assertion, and decide: is the code
      wrong, the threshold wrong, or the regex wrong? Fix the right one.
- [ ] Tighten loose regexes (`(?i)ml[-_ ]?dsa[-_ ]?65`) to the real output.
- [ ] Record observed numbers in `expected_numbers`.
- [ ] Add one golden fixture per protocol.
- [x] TLS: confirm the key-log decryption path produces ML-DSA OIDs in
      `metrics.protocol.tls.decrypted` for `tls-auth-mldsa65-mtls`.
- [ ] MACsec: confirm 14 vs ~42 EAPOL frames (upstream numbers).

Done when: `make smoke` passes on all five stacks.

## Phase 4 - Demo polish (day 5)

- [ ] Walk `docs/DEMO_SCRIPT.md` end to end with a timer; trim anything that drags.
- [ ] Add a "presenter mode" toggle that enlarges the ladder and narration.
- [ ] Export: a one-click "copy ladder as SVG" for slides and LinkedIn posts.
- [ ] Record a 3-minute screen capture of the classical -> hybrid -> ML-DSA story.

## Phase 5 - Stage 2: real Cisco gear (optional, needs hardware)

See `docs/DEPLOY_CISCO.md`.

- [ ] Import an IOS XE Embedded Packet Capture (EPC) export via "Import a capture";
      verify the IKEv2 decoder labels the router's ML-KEM proposal correctly.
- [ ] Side-by-side compare: container ML-DSA-65 vs C8000 ML-DSA-65 (Cisco measured
      7 frames / 7 KB -> 20 frames / 24 KB).
- [ ] Optional: an Ansible runner sidecar that executes the upstream
      `deploy/c8000/automation` playbooks and streams their output as run steps.

## Phase 6 - Stretch

- [ ] MACsec data plane on a Linux host with `CONFIG_MACSEC` (static CAK via
      `macsec_linux`), showing 0x88e5 frames after the PQ EAP-TLS handshake.
- [ ] WireGuard + Rosenpass as a fifth protocol family.
- [ ] Per-scenario latency benchmarking (50 handshakes, p50/p95).
- [ ] CI: GitHub Actions running `make test` on every push, and `make smoke` on a
      self-hosted runner with Docker.
