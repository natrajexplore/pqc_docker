# PQC WireScope

**Watch post-quantum handshakes happen, packet by packet.**

![License: MIT](https://img.shields.io/badge/license-MIT-blue)
![Scenarios verified](https://img.shields.io/badge/scenarios%20verified-14%2F18-brightgreen)
![Protocols](https://img.shields.io/badge/protocols-IKEv2%20%7C%20TLS%201.3%20%7C%20SSH%20%7C%20MACsec-informational)
![Algorithms](https://img.shields.io/badge/PQC-ML--KEM%20%7C%20ML--DSA-purple)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB)
![Docker Compose](https://img.shields.io/badge/docker%20compose-2.20%2B-2496ED)

PQC WireScope runs ML-KEM key exchange and ML-DSA authentication across
**IPsec/IKEv2, TLS 1.3, SSH and MACsec/802.1X** in Docker containers, captures
every packet end to end, and streams the capture live into a web UI:

- a **sequence diagram** whose arrows thicken with byte count, so a hybrid
  ML-KEM handshake visibly outweighs a classical one;
- a **decoded packet table** with a full dissection tree and hex for every frame;
- a **two-pillar verdict** (key exchange, authentication) that says whether each
  pillar was *seen on the wire*, only *reported by an endpoint*, or merely *declared*.

![Hybrid IKEv2 run: thick ML-KEM arrows, fragmented IKE_INTERMEDIATE, ESP data plane](docs/img/ui-hybrid.png)

It builds on Julio Gomez's [juliogomez/pqc](https://github.com/juliogomez/pqc)
labs ("learn it in containers, deploy it on real gear") and the Cisco DevNet
live stream [*Post-Quantum Cryptography in the Real World* (Ep. 120)](https://www.youtube.com/live/9v_nuDHSd5I).
The upstream container images are built **unmodified**; this project adds the
automation, capture, analysis and visualisation layers.

> **Lab only.** Every key, certificate, PSK and PPK here is for throwaway containers.
> Never reuse any of it on a real network.

---

## Contents

- [Why this exists](#why-this-exists)
- [At a glance: four protocols, one question](#at-a-glance-four-protocols-one-question)
- [PQC primer](#pqc-primer)
- [Measured results](#measured-results)
- [Scenarios](#scenarios)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Evidence levels](#evidence-levels-why-wire-matters)
- [API](#api)
- [Configuration](#configuration)
- [Security model](#security-model)
- [Observability](#observability)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Project status](#project-status)
- [Learn, then deploy](#learn-then-deploy)
- [Credits and licence](#credits-and-licence)

---

## Why this exists

"Post-quantum enabled" is easy to claim and hard to see. A vendor data sheet or
an endpoint log line says ML-KEM was negotiated; a packet capture **proves** it.
WireScope makes the proof the default view: every claim in the UI is backed by
bytes on the wire, and when the wire cannot show something (an encrypted
certificate, for example) the UI says so instead of guessing.

It is also a teaching tool. Running the classical and post-quantum variants of
the same handshake side by side answers the questions people actually ask:
*How much bigger is it? Does it add round trips? Does it fragment? Can it be
silently downgraded?*

---

## At a glance: four protocols, one question

*"Is this connection post-quantum?"* gets a different answer, at a different cost,
in every protocol. These are the results from real runs in this lab:

| | IKEv2 / IPsec | TLS 1.3 | SSH | MACsec / 802.1X |
|---|---|---|---|---|
| Hybrid key exchange | X25519 + ML-KEM in a **separate** IKE_INTERMEDIATE exchange | `X25519MLKEM768` inside the normal hellos | `mlkem768x25519-sha256` | hybrid ML-KEM inside EAP-TLS 1.3 |
| Extra round trips | **+1** | 0 | 0 | 0 |
| Handshake growth (KEX only) | 3.4x (ML-KEM-768), 4.3x (ML-KEM-1024) | key shares 32 B -> 1,216 / 1,120 B | KEX_ECDH_INIT 44 B -> 1,228 B | *to measure* |
| Post-quantum by default? | no - configure proposals | yes in OpenSSL 3.5 | **yes**, zero config | needs `tls_flags` in hostapd |
| PQ authentication tested | ML-DSA-44 / 65 certificates | ML-DSA-65 certificates | composite Ed25519 + ML-DSA-44 keys | ML-DSA-44 EAP certificates |
| Auth growth | IKE_AUTH 2 -> 16 messages (ML-DSA-65) | certificate 527 B -> 5,652 B | KEX reply 1,276 B -> 5,044 B | *to measure* |
| Best evidence for auth | endpoint (IKE_AUTH is encrypted) | **wire** (lab key log decrypts it) | **wire** (host key is cleartext) | wire via key log (planned) |
| Downgrade behaviour | set by the configured proposals (not a scenario yet) | server's group choice visible on the wire | **loud**: client prints a WARNING | **silent** TLS 1.2 unless the client pins 1.3 |

The MACsec column describes what its scenarios are built to show; it has not yet
been run on real containers (see [project status](#project-status)).

The pattern: post-quantum key exchange is cheap in bytes and free in round trips
everywhere except IKEv2; post-quantum authentication is where the size really
grows; and only some protocols tell you when you've been downgraded.

---

## PQC primer

The two NIST standards this lab exercises, and the sizes that explain every
number in the results below:

| Algorithm | Standard | Role | Public key | Ciphertext / signature |
|---|---|---|---:|---:|
| X25519 (classical, for comparison) | RFC 7748 | key exchange | 32 B | 32 B |
| ML-KEM-768 | FIPS 203 | key encapsulation | 1,184 B | 1,088 B |
| ML-KEM-1024 | FIPS 203 | key encapsulation | 1,568 B | 1,568 B |
| ML-DSA-44 | FIPS 204 | signatures | 1,312 B | 2,420 B |
| ML-DSA-65 | FIPS 204 | signatures | 1,952 B | 3,309 B |

**Hybrid** means classical and post-quantum together: the session is safe as long
as *either* holds. That is why the TLS key shares measured here are exactly
1,216 B (1,184 + 32) from the client and 1,120 B (1,088 + 32) from the server.

How each protocol carries them:

| Protocol | Mechanism | Reference |
|---|---|---|
| IKEv2 | Multiple key exchanges (ADDKE transforms) | RFC 9370 |
| IKEv2 | IKE_INTERMEDIATE exchange | RFC 9242 |
| IKEv2 | Message fragmentation (needed for ML-KEM / ML-DSA) | RFC 7383 |
| IKEv2 | Post-quantum preshared keys (PPK) | RFC 8784 |
| TLS 1.3 | `X25519MLKEM768` hybrid group (0x11EC) | draft-ietf-tls-ecdhe-mlkem |
| TLS 1.3 / X.509 | ML-DSA in certificates | IETF LAMPS ML-DSA certificate profile |
| SSH | `mlkem768x25519-sha256` | OpenSSH 9.9+ (default since 10.0) |
| MACsec | EAP-TLS 1.3 derives the MSK -> CAK -> SAK chain | RFC 9190, IEEE 802.1X |

Exact codepoints, and how to recognise each one in a capture, are in
[docs/PQC_WIRE_REFERENCE.md](docs/PQC_WIRE_REFERENCE.md).

---

## Measured results

Real runs on Docker Desktop (WSL2 kernel 6.18), strongSwan 6.0 (`ml` plugin) and
the strongSwan `ml-dsa` branch (6.1.0), captured inside the responder's network
namespace. Bytes are full Ethernet frame lengths of the handshake.

### IKEv2 key exchange

| Scenario | Frames | Handshake bytes | vs classical | Fragments | Verdict |
|---|---:|---:|---:|---:|---|
| Classical X25519 | 4 | 1,098 | 1.0x | 0 | classical (wire) |
| RFC 8784 PPK | 4 | 1,139 | 1.04x | 0 | pq-ppk (wire) |
| Hybrid X25519 + ML-KEM-768 | 7 | 3,735 | **3.4x** | 2 | pq-hybrid (wire) |
| Hybrid X25519 + ML-KEM-1024 | 8 | 4,742 | **4.3x** | 4 | pq-hybrid (wire) |

ML-KEM rides in an extra **IKE_INTERMEDIATE** round trip (RFC 9242 / RFC 9370):
the ML-KEM-768 public key (1,184 B) does not fit one frame, so the request is
split into two IKE fragments; the response (1,199 B frame) carries the ciphertext.

### IKEv2 authentication (all with hybrid ML-KEM-768 key exchange)

| Certificates | Frames | Handshake bytes | IKE_AUTH messages | Auth verdict |
|---|---:|---:|---:|---|
| ECDSA P-256 | 7 | 4,937 | 2 | classical (endpoint) |
| ML-DSA-44 | 17 | 17,949 | 12 (6 fragments each way) | pq ML-DSA-44 (endpoint) |
| ML-DSA-65 | 21 | 23,253 | 16 (8 fragments each way) | pq ML-DSA-65 (endpoint) |

For comparison, Cisco reports a C8000 on IOS XE 26.2 going from
*7 frames / 7 KB* (classical) to *20 frames / 24 KB* with ML-DSA-65 - the
container numbers land in the same place. Authentication is **endpoint**
evidence because IKE_AUTH is encrypted; see [evidence levels](#evidence-levels-why-wire-matters).

Every one of these runs also passed its data-plane check: three pings become six
ESP packets and no cleartext ICMP crosses the wire.

### TLS 1.3 (OpenSSL 3.5.7)

| Scenario | Key share (client / server) | Certificate messages | KEX verdict | Auth verdict |
|---|---|---|---|---|
| Classical x25519 | 32 B / 32 B | ECDSA 527 B | classical (wire) | classical (wire) |
| Hybrid X25519MLKEM768 | 1,216 B / 1,120 B | ECDSA 527 B | pq-hybrid (wire) | classical (wire) |
| ECDSA mutual TLS | 1,216 B / 1,120 B | ECDSA 527 B + 488 B | pq-hybrid (wire) | classical (wire) |
| ML-DSA-65 mutual TLS | 1,216 B / 1,120 B | **ML-DSA-65 5,652 B + 5,614 B** | pq-hybrid (wire) | **pq ML-DSA-65 (wire)** |

Unlike IKEv2, hybrid ML-KEM adds **no round trip** in TLS: the larger key shares
ride in the same ClientHello and ServerHello. ML-DSA-65 makes each Certificate
message about 11x larger. TLS authentication counts as *wire* evidence here because
the lab key log lets the analyzer decrypt TLS 1.3's encrypted Certificate message.

### SSH (OpenSSH 10.4p1)

| Scenario | KEX_ECDH_INIT | KEX_ECDH_REPLY | KEX verdict | Host key verdict |
|---|---:|---:|---|---|
| Default (no config) | 1,228 B | 1,276 B | pq-hybrid `mlkem768x25519-sha256` (wire) | classical Ed25519 (wire) |
| Server forces classical | 44 B | 188 B | classical `curve25519-sha256` (wire) + client **WARNING** | classical Ed25519 (wire) |
| Composite host + user keys | 1,228 B | **5,044 B** | pq-hybrid (wire) | pq `ssh-mldsa44-ed25519@openssh.com` (wire) |

SSH is the easy case: ML-KEM is the default with zero configuration, and the host
key travels in cleartext, so both pillars are *wire* evidence. OpenSSH prints
`WARNING: connection is not using a post-quantum key exchange` - but only when the
*server* imposes the classical choice; a client that forces it with
`-o KexAlgorithms` is treated as deliberate and gets no warning.

---

## Scenarios

18 declarative scenarios in [`scenarios/`](scenarios/), documented in
[docs/SCENARIOS.md](docs/SCENARIOS.md). Each one sets up a posture, starts the
capture, drives the handshake, pushes data through it, and checks assertions
against the capture.

| Stack | Scenario | Pillar | What it shows | Verified |
|---|---|---|---|---|
| `ipsec` | `ipsec-kex-classical` | key exchange | X25519-only baseline | yes |
| | `ipsec-kex-hybrid-mlkem768` | key exchange | X25519 + ML-KEM-768 via IKE_INTERMEDIATE | yes |
| | `ipsec-kex-hybrid-mlkem1024` | key exchange | X25519 + ML-KEM-1024, fragmented both ways | yes |
| | `ipsec-kex-ppk` | key exchange | RFC 8784 post-quantum preshared key | yes |
| `ipsec-auth` | `ipsec-auth-ecdsa` | authentication | ECDSA P-256 certificates | yes |
| | `ipsec-auth-mldsa44` | authentication | ML-DSA-44 certificates | yes |
| | `ipsec-auth-mldsa65` | authentication | ML-DSA-65 certificates | yes |
| `tls` | `tls-kex-classical` | key exchange | x25519 baseline | yes |
| | `tls-kex-hybrid` | key exchange | X25519MLKEM768 with no extra round trip | yes |
| | `tls-auth-ecdsa-mtls` | authentication | ECDSA mutual TLS | yes |
| | `tls-auth-mldsa65-mtls` | both | ML-DSA-65 mutual TLS, certificate algorithm read off the wire via a lab key log | yes |
| `ssh` | `ssh-kex-default` | key exchange | `mlkem768x25519-sha256` is OpenSSH 10.4's default | yes |
| | `ssh-kex-downgrade` | key exchange | a server that only offers classical KEX - and OpenSSH warns out loud | yes |
| | `ssh-auth-composite` | both | composite Ed25519 + ML-DSA-44 host and user keys | yes |
| `macsec` | `macsec-eaptls-ecdsa` | key exchange | EAP-TLS 1.3 with hybrid ML-KEM | pending |
| | `macsec-eaptls-mldsa44` | both | ML-DSA-44 EAP certificates (about 3x the EAPOL frames) | pending |
| | `macsec-downgrade-tls12` | key exchange | the **silent** downgrade to classical TLS 1.2 | pending |
| | `macsec-downgrade-pinned-client` | key exchange | a client pin turns the downgrade into a loud failure | pending |

**Compare** any two runs side by side (bytes, frames, flights, fragments,
duration), and **import** a pcap from a real router (IOS XE Embedded Packet
Capture) to analyse it with the same decoder.

![Classical vs hybrid compare view](docs/img/ui-compare.png)

---

## Quick start

### Requirements

| | |
|---|---|
| Docker | Engine with **Compose v2.20+** (`include:` support) |
| Disk | about 6 GB for images |
| Memory | 8 GB for Docker is comfortable; build stacks one at a time on less |
| Host tools | `git`, `bash`, `openssl`, `make` (optional - every target is a thin wrapper) |
| Kernel | XFRM for the IPsec ESP data plane; `CONFIG_MACSEC` only for the optional MACsec data plane |

### Run it

```bash
git clone --recurse-submodules https://github.com/natrajexplore/pqc_docker.git
cd pqc_docker
make bootstrap                 # upstream submodule + random lab secrets in .env
make preflight                 # what works on this host (XFRM, MACsec, free subnets)
make up PROFILES="ipsec"       # first build compiles strongSwan: 5-10 minutes
# open http://127.0.0.1:8080 and run a scenario
```

Add stacks as you need them: `make up PROFILES="ipsec ipsec-auth tls ssh macsec"`.
The management plane (UI, API, socket proxy) always runs.

### Without `make` (e.g. Windows + Git Bash)

```bash
./scripts/bootstrap.sh
./scripts/preflight.sh
docker network create --driver bridge --subnet 172.29.0.0/24 pqcw_mgmt
docker volume create pqcw_captures
docker compose --profile ipsec build ipsec-responder   # build images one at a time
docker compose --profile ipsec build cap-ipsec backend frontend
docker compose --profile ipsec up -d --no-build
```

### No Docker at all

`scripts/dev_mock_server.py` serves the real API and UI with a fake Docker and a
fake capture agent, so you can explore the interface and the analyzer anywhere:

```bash
cd frontend && npm install && npm run build && cd ..
pip install -e "backend[dev]"
cd scripts && python -m uvicorn dev_mock_server:app --port 8765
```

---

## How it works

```
 browser ──► frontend (nginx, 127.0.0.1:8080) ──► backend (FastAPI)
                                                    │  exec only, private network
                                                    ├──► socket-proxy ──► docker
                                                    │  HTTP + WS, X-PQCW-Token
                                                    └──► capture agent ─┐ shares the netns of
                                                                        ▼ one lab node
                 initiator ◄──── IKEv2 / TLS / SSH / EAPOL ────► responder
```

1. `POST /api/runs` starts a scenario; one run per stack at a time.
2. The orchestrator executes the scenario's steps with `docker exec` through a
   locked-down socket proxy (switch the swanctl variant, mint certificates, start
   daemons, wait for them).
3. A **capture agent** sidecar living in the responder's network namespace runs
   `dumpcap` (authoritative pcapng) and `tshark` (live EK JSON) on the lab interface.
4. Every packet is **normalized** - including by our own dependency-free IKEv2
   decoder, because distro dissectors still print new codepoints as "Unknown" - and
   pushed to the UI over a WebSocket as it arrives.
5. Cleanup steps always run; then metrics, assertions and the two-pillar verdict
   are computed and `run.json` is stored next to the pcapng.

### Life of a run

```mermaid
sequenceDiagram
    autonumber
    participant UI as Browser UI
    participant API as Backend (FastAPI)
    participant DP as socket-proxy
    participant AG as Capture agent
    participant LAB as Lab nodes
    UI->>API: POST /api/runs {scenario_id}
    API-->>UI: run_id, then WebSocket /ws/runs/{id}
    API->>DP: exec setup steps (variant, certs, daemons)
    DP->>LAB: docker exec
    API->>AG: POST /captures (X-PQCW-Token)
    AG->>AG: dumpcap -> pcapng, tshark -> EK JSON
    API->>DP: exec the handshake + data plane
    LAB-->>AG: packets on the lab interface
    AG-->>API: packet stream (WebSocket)
    API-->>UI: normalized packets, live
    API->>AG: POST /captures/{id}/stop
    API->>DP: cleanup steps (always run)
    API->>API: metrics, assertions, two-pillar verdict
    API-->>UI: run.result
```

### What the wire shows: hybrid IKEv2 with ML-KEM-768

Frame sizes from a real `ipsec-kex-hybrid-mlkem768` run. The extra
IKE_INTERMEDIATE round trip is the whole cost of going post-quantum in IKEv2:

```mermaid
sequenceDiagram
    participant I as Initiator 172.30.0.2
    participant R as Responder 172.30.0.3
    I->>R: IKE_SA_INIT req - KE X25519 + ADDKE1 ML-KEM-768 offered (290 B)
    R->>I: IKE_SA_INIT resp - X25519 + ML-KEM-768 selected (298 B)
    Note over I,R: Post-quantum part, encrypted under the X25519 keys
    I->>R: IKE_INTERMEDIATE req, fragment 1/2 (1,294 B)
    I->>R: IKE_INTERMEDIATE req, fragment 2/2 (112 B)
    R->>I: IKE_INTERMEDIATE resp - ML-KEM ciphertext (1,199 B)
    I->>R: IKE_AUTH req (283 B)
    R->>I: IKE_AUTH resp (259 B)
    Note over I,R: Child SA up - three pings become six ESP packets
```

Details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```
compose.yaml          root project: include: of every stack
stacks/<stack>/       compose file, protocol configs, credential scripts per profile
capture-agent/        sidecar: dumpcap -> pcapng, tshark -> live EK JSON
backend/app/          FastAPI: scenarios, orchestrator, docker exec, analyzer
backend/tests/        offline unit tests + golden pcap fixtures
scenarios/*.yaml      declarative runs: steps, capture filter, assertions
frontend/src/         React + Vite UI
scripts/              bootstrap, secrets, preflight, smoke, dev mock server
docs/                 architecture, plan, learning path, scenarios, wire reference
vendor/juliogomez-pqc upstream labs (git submodule, read-only)
```

---

## Evidence levels: why "wire" matters

| Level | Meaning | Example |
|---|---|---|
| **wire** | decoded from cleartext handshake bytes (or a lab key-log decryption) | ML-KEM-768 selected in the IKE_SA_INIT response |
| **endpoint** | reported by a peer's own tooling | `pki --print` says the installed certificate is ML-DSA-65 |
| **declared** | stated by the scenario file | fallback when nothing better exists |

The code never upgrades evidence. IKEv2 and TLS 1.3 encrypt certificates, so
their authentication verdicts are *endpoint* - unless a TLS scenario uses a
lab-only key log to decrypt the Certificate message, which makes it *wire*.

A capture inside the receiving peer also sees each decrypted ESP packet a second
time, re-injected by the kernel with the same timestamp. The analyzer tags those
frames `decap-copy` and keeps them out of "cleartext on the wire" checks, while a
real leak (no matching ESP frame) still fails.

---

## API

Everything the UI does goes through this API (served under `/api` by the
frontend's nginx at `http://127.0.0.1:8080`), so you can script the lab too.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness, scenario count, scenario load errors |
| GET | `/api/stacks` | running lab containers and capture-agent health |
| GET | `/api/scenarios` | catalogue, with `available` and what is `missing` |
| POST | `/api/scenarios/reload` | re-read `scenarios/*.yaml` |
| POST | `/api/runs` `{"scenario_id": ...}` | start a run, returns `run_id` |
| GET | `/api/runs` | run summaries, newest first (`?limit=1..1000`) |
| GET | `/api/runs/{id}` | one run: steps, metrics, assertions, verdict |
| GET | `/api/runs/{id}/packets` | normalized packets |
| GET | `/api/runs/{id}/packets/{n}` | full dissection tree + hex (`?decrypt=true` uses the lab key log) |
| GET | `/api/runs/{id}/pcap` | download the pcapng |
| POST | `/api/runs/{id}/abort` | abort a running scenario |
| GET | `/api/compare?a=..&b=..` | side-by-side metrics of two runs |
| POST | `/api/imports` | upload a pcap (max 50 MB), e.g. a router's EPC export |
| WS | `/ws/runs/{id}` | event replay, then live events |

```bash
# run a scenario from the command line and print its verdict
run=$(curl -s -X POST 127.0.0.1:8080/api/runs -H 'content-type: application/json' \
        -d '{"scenario_id":"tls-kex-hybrid"}' | python -c 'import sys,json;print(json.load(sys.stdin)["run_id"])')
until curl -s 127.0.0.1:8080/api/runs/$run | grep -qE '"status":"(completed|failed|aborted)"'; do sleep 1; done
curl -s 127.0.0.1:8080/api/runs/$run | python -c 'import sys,json;print(json.load(sys.stdin)["verdict"]["summary"])'
```

Browsers on other sites cannot call it: requests with a foreign `Origin` or an
unexpected `Host` get `403` (see [security model](#security-model)).

---

## Configuration

All settings live in `.env` (created by `make secrets` / `make bootstrap`, gitignored,
mode 600). See [`.env.example`](.env.example).

| Variable | Default | Purpose |
|---|---|---|
| `PQCW_UI_PORT` | `8080` | UI port, published on `127.0.0.1` only |
| `PQCW_IKE_PSK`, `PQCW_IKE_PPK_HEX` | generated | IKEv2 PSK and RFC 8784 PPK |
| `PQCW_AGENT_TOKEN` | generated | backend <-> capture agent token; agents refuse to start without it |
| `PQCW_ALLOWED_HOSTS` | `127.0.0.1,localhost,::1` | host names the UI may be reached by (CSRF / DNS-rebinding guard) |
| `PQCW_LOG_LEVEL` | `INFO` | backend log level |
| `PQCW_LOG_FORMAT` | `text` | `text` or `json` (one object per line) |
| `PQCW_ALLOW_TLS_KEYLOG` | `true` | lab-only TLS key logs for wire evidence of TLS certificates |
| `PQCW_RUN_TIMEOUT_S` | `120` | hard limit for one scenario run |
| `PQCW_STRONGSWAN_MLDSA_REF` | `ml-dsa` | branch/tag of the experimental strongSwan ML-DSA build |

---

## Security model

WireScope demonstrates security protocols, so it tries not to be the weakest
thing on your laptop. Highlights (full model in [docs/SECURITY.md](docs/SECURITY.md)):

- UI on **loopback only**; backend and capture agents are not published at all.
- The API rejects requests with an unexpected `Host` or a cross-site `Origin`,
  so a web page you visit cannot drive it (CSRF, cross-site WebSocket, DNS rebinding).
- The backend never mounts the Docker socket. It talks to a **socket proxy**
  (pinned by digest) on a private internal network that lab containers cannot reach.
- Capture agents bind to the management network, require a random token compared
  in constant time, and fail closed without one.
- No `privileged` containers; `cap_drop: [ALL]` plus only the capabilities each
  role needs; `no-new-privileges`; read-only root filesystems for UI and API.
- Secrets are generated per checkout into `.env`; PKI is minted at run time into
  named volumes, never into the working tree.

Known gap, documented rather than hidden: the socket proxy still permits container
creation, so a compromised backend could escalate. Closing it needs a proxy with
per-method path allowlists.

---

## Observability

- **Request ids** end to end: nginx generates one, logs it as `rid=`, forwards it as
  `X-Request-ID`; the backend echoes it and stamps it on every log line - including
  the lines of the run that request started.
- **Run lifecycle** logged at INFO: start, step failures, finish with status,
  packet count and duration; pcap imports too.
- **Security events** logged: rejected Host/Origin (backend), bad agent tokens (agents).
- `PQCW_LOG_FORMAT=json` for Loki, ELK or any log shipper.
- **Healthchecks** on backend, frontend and capture agents (and lab nodes whose
  upstream image defines one): `docker compose ps`.

```bash
make logs                                    # backend + every capture agent
docker compose logs backend | grep <rid>     # everything one request did
```

---

## Development

```bash
make test        # backend pytest + frontend typecheck/build (no Docker needed)
make lint        # ruff, shellcheck, tsc
make smoke       # every available scenario through the real API
```

- **Tests**: analyzer, IKEv2 decoder, orchestrator (fake Docker), API guard, and
  golden fixtures - real captures in `backend/tests/fixtures/` replayed through
  tshark -> normalizer -> assertions -> verdict (skipped where tshark is absent).
- **Adding a scenario**: copy the closest file in `scenarios/` (file name = `id`),
  `POST /api/scenarios/reload`, run it, calibrate thresholds from the real capture
  and record what you saw in `expected_numbers`. See [CLAUDE.md](CLAUDE.md).
- **Building it with Claude Code**: the repo ships project commands -
  `/next-phase`, `/run-scenario <id>`, `/verify-wire <run_id>`, `/add-scenario <idea>` -
  that follow [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md).

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `preflight` says XFRM missing on Docker Desktop | older preflight probed with busybox `ip`; current probe installs iproute2. XFRM works on the WSL2 kernel. |
| `kernel MACsec NOT available` | normal on Docker Desktop. EAP-TLS handshake scenarios still work; only the 0x88e5 data plane needs it. |
| Build dies with `rpc error ... EOF`, Docker stops responding | memory pressure from parallel source builds. Restart Docker and build one image at a time; give WSL more memory in `%UserProfile%\.wslconfig`. |
| After such a crash a container fails with odd import errors | the build cache kept truncated (0-byte) files. Rebuild that image with `docker compose build --no-cache <service>`. |
| Upstream entrypoints fail with `bad interpreter` on Windows | files were checked out with CRLF. The repo's `.gitattributes` forces LF; for the submodule set `git -C vendor/juliogomez-pqc config core.autocrlf false` and re-checkout. |
| Capture agent exits immediately | `PQCW_AGENT_TOKEN` missing - run `make secrets` and restart the stack. |
| API answers `403 request rejected` | you reach the UI by a host name not in `PQCW_ALLOWED_HOSTS`; add it. |
| A step that stops a daemon fails with exit code 143 | `pkill -f '<pattern>'` run via `sh -c` matches its own command line and kills itself. Use the bracket form `pkill -f '[o]penssl s_server'`. |
| SSH runs talk to a stale `sshd` | the upstream SSH image has no `pkill`; scenarios stop `sshd` via its PID file (`/run/sshd.pid`). Keep that pattern in new SSH scenarios. |
| `docker exec ... /usr/local/...` fails with `C:/Program: not found` in Git Bash | Git Bash rewrites absolute paths. Prefix the command with `MSYS_NO_PATHCONV=1`. |
| tshark field warnings in `make logs` (`dropped: ...`) | field names change between Wireshark versions (4.4 uses `isakmp.exchangetype`, `tls.record.opaque_type`). Fix `capture-agent/agent/fields.py`, then copy it to `backend/app/analyzer/fields.py`. |

---

## FAQ

**Is this a real VPN / production configuration?**
No. It is a lab for seeing and measuring post-quantum handshakes. Every secret is
throwaway, the TLS key log deliberately weakens confidentiality, and the
configurations favour visibility over hardening.

**Why "hybrid" instead of pure ML-KEM?**
ML-KEM is new. Combining it with X25519 means the session stays secure if either
algorithm is broken - the approach IETF, NIST guidance and vendors (including
Cisco IOS XE) use for migration.

**Why is IPsec authentication only "endpoint" evidence when TLS gets "wire"?**
Both encrypt their certificates. TLS scenarios write a lab key log that lets the
analyzer decrypt the Certificate message and read the algorithm from the bytes.
IKEv2 has no equivalent here, so the certificate algorithm comes from `pki --print`
on the peer, and the UI says so.

**Can I analyse captures from real routers?**
Yes. Export an Embedded Packet Capture from IOS XE and use *Import a capture* (or
`POST /api/imports`). The same decoder labels the router's ML-KEM proposals. See
[docs/DEPLOY_CISCO.md](docs/DEPLOY_CISCO.md).

**Does it run on Windows / macOS?**
Yes, with Docker Desktop. Everything except the kernel MACsec data plane works;
on Windows use Git Bash and see [Without `make`](#without-make-eg-windows--git-bash).

**How do I add my own scenario?**
Copy the closest YAML in `scenarios/`, keep the file name equal to its `id`,
reload, run it, then calibrate thresholds from the real capture. The full recipe is
in [CLAUDE.md](CLAUDE.md#adding-a-scenario) and [docs/SCENARIOS.md](docs/SCENARIOS.md).

---

## Project status

| Phase | State |
|---|---|
| Scaffold, analyzer, orchestrator, UI, offline tests | done |
| 1 - stacks up (mgmt + IPsec), socket proxy pinned, capture fields verified | done |
| 2 - IPsec key exchange and authentication on real containers | done: 7/7 scenarios pass, numbers recorded, golden fixtures added |
| 3 - calibrate TLS, SSH, MACsec | in progress: TLS 4/4 and SSH 3/3 pass on real containers; MACsec next |
| 4 - demo polish (presenter mode, ladder export) | planned |
| 5 - real Cisco gear (EPC import, C8000 compare) | optional |

Tracked in [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md).

---

## Learn, then deploy

- [docs/LEARNING_PATH.md](docs/LEARNING_PATH.md) - four weeks from "what is ML-KEM" to a migration plan
- [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) - a 12-minute talk track that follows the UI
- [docs/DEPLOY_CISCO.md](docs/DEPLOY_CISCO.md) - mapping each scenario to IOS XE 26.2, importing router captures
- [docs/PQC_WIRE_REFERENCE.md](docs/PQC_WIRE_REFERENCE.md) - sizes and codepoints to look for in a capture
- [docs/SECURITY.md](docs/SECURITY.md) - the lab's own security model

---

## Credits and licence

Upstream labs, Dockerfiles and the learn/deploy structure: Julio Gomez,
[juliogomez/pqc](https://github.com/juliogomez/pqc) (MIT), pinned as a submodule.
Configuration files and credential scripts adapted from it say so in their
headers. See [NOTICE.md](NOTICE.md).

This project is released under the [MIT licence](LICENSE).
