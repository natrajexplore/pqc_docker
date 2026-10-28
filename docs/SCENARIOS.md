# Scenarios

A scenario is one reproducible, captured run. It lives in `scenarios/<id>.yaml`
and is validated by `backend/app/models.py` on load (`POST /api/scenarios/reload`
re-reads them without a restart).

## Catalogue

| Stack | Scenario | Pillar | What it proves |
|---|---|---|---|
| ipsec | `ipsec-kex-classical` | KEX | baseline: X25519 only, 4 IKE messages |
| ipsec | `ipsec-kex-hybrid-mlkem768` | KEX | ADDKE1 ML-KEM-768 in IKE_INTERMEDIATE, fragmented, +1 RTT |
| ipsec | `ipsec-kex-hybrid-mlkem1024` | KEX | both IKE_INTERMEDIATE directions fragment |
| ipsec | `ipsec-kex-ppk` | KEX | RFC 8784 PPK: USE_PPK, no IKE_INTERMEDIATE |
| ipsec-auth | `ipsec-auth-ecdsa` | AUTH | hybrid KEX + ECDSA certs, compact IKE_AUTH |
| ipsec-auth | `ipsec-auth-mldsa44` | both | ML-DSA-44 certs, IKE_AUTH fragments |
| ipsec-auth | `ipsec-auth-mldsa65` | both | ML-DSA-65 (what IOS XE 26.2 ships) |
| tls | `tls-kex-classical` | KEX | x25519, 32-byte key shares |
| tls | `tls-kex-hybrid` | KEX | X25519MLKEM768 (0x11ec): 1216 / 1120-byte shares, no extra RTT |
| tls | `tls-auth-ecdsa-mtls` | AUTH | mTLS with ECDSA, decrypted with lab key log |
| tls | `tls-auth-mldsa65-mtls` | both | mTLS with ML-DSA-65; OIDs visible after decryption |
| ssh | `ssh-kex-default` | KEX | mlkem768x25519-sha256 with zero config |
| ssh | `ssh-kex-downgrade` | KEX | forced curve25519-sha256, OpenSSH warns |
| ssh | `ssh-auth-composite` | both | composite Ed25519+ML-DSA-44 host/user keys |
| macsec | `macsec-eaptls-ecdsa` | KEX | EAP-TLS 1.3 negotiates X25519MLKEM768 (~14 frames) |
| macsec | `macsec-eaptls-mldsa44` | both | ML-DSA EAP certs (~42 frames) |
| macsec | `macsec-downgrade-tls12` | KEX | **silent** downgrade: EAP success, TLS 1.2, no ML-KEM (red by design) |
| macsec | `macsec-downgrade-pinned-client` | KEX | client pins TLS 1.3: downgrade fails closed (green by design) |

Comparison groups (`group:`) pair naturally in the compare view:
`ipsec-kex`, `ipsec-auth`, `tls-kex`, `tls-auth`, `ssh`, `macsec`.

## Schema

```yaml
id: ipsec-kex-hybrid-mlkem768     # must equal the file name
title: "Human title"
protocol: ipsec | tls | ssh | macsec
stack: ipsec                       # compose profile that must be running
pillar: key-exchange | authentication | both
group: ipsec-kex                   # comparable scenarios share a group
order: 20                          # position within the protocol in the rail
summary: >                         # shown under the title; plain language
upstream_lab: learn/ipsec/key-exchange
learn_more: [urls]
nodes:                             # logical name -> container_name
  initiator: pqcw-ipsec-initiator
endpoints:                         # who is "left" and "right" on the ladder
  left:  {name: Initiator, ip: 172.30.0.2}
  right: {name: Responder, mac: "${aut_mac}"}   # ip or mac; ${vars} allowed
capture:
  agent: pqcw-cap-ipsec            # agent container (must be running)
  host: ipsec-responder            # mgmt DNS name of the node whose netns it shares
  bpf: "udp port 500 or udp port 4500 or esp"
keylog: {node: client, path: /tmp/tls.keys}     # optional, TLS only, lab only
declared:                          # fallback verdict when the wire can't say
  key_exchange: pq-hybrid
  authentication: classical
  authentication_algorithm: PSK
steps: [...]                       # must include capture_start before capture_stop
cleanup: [...]                     # always runs, failures ignored
assertions: [...]
expected_numbers: {...}            # reference values shown to the reader
```

### Step actions

| action | fields | behaviour |
|---|---|---|
| `exec` (default) | `exec: [{node, cmd, detach, timeout, allow_fail, env}]`, `expect: {regex, absent}` | runs each command; list `cmd` = argv, string = `sh -c`; non-detached commands are wrapped in `timeout`; non-zero exit fails the step unless `allow_fail` |
| `wait_for` | `wait_for: {node, cmd, regex, timeout, interval}` | polls until the output matches |
| `resolve` | `exec: [one]`, `var: name` | stores the last output line as `${name}` |
| `sleep` | `seconds` | pause |
| `capture_start` / `capture_stop` | - | start/stop the agent; packets stream to the UI in between |

Every step may carry `narration:` - shown prominently while that step runs, so
the UI doubles as a presenter's script.

### Assertion kinds

| kind | expect | evidence |
|---|---|---|
| `ikev2.selected_additional_ke` | `methods: [ML_KEM_768]` or `none: true` | wire (IKE_SA_INIT response) |
| `ikev2.exchange_count` | `exchange, min, max` | wire |
| `ikev2.notify` | `notify: USE_PPK` | wire |
| `tls.server_group` | `group: X25519MLKEM768` or `not: …` | wire (ServerHello) |
| `tls.client_offers_group` | `group` | wire (ClientHello) |
| `tls.version` | `version: "TLS 1.3"` | wire |
| `tls.decrypted_cert_pq` | `post_quantum: true/false` | wire, via lab key log |
| `ssh.negotiated_kex` | `kex` | wire (both KEXINITs, RFC 4253 rule) |
| `ssh.negotiated_host_key` | `algorithm` or `contains` | wire |
| `eap.frames` | `min, max` | wire |
| `count` | `proto, tag, min, max` | wire (skips `decap-copy` frames: the receiving peer's kernel re-injecting a decrypted ESP packet, same direction within 1 ms - never on the wire) |
| `step_output` | `step, regex, absent` | endpoint; name it `auth-*` to credit the auth pillar |

## Writing a good scenario

- One idea per scenario, and a baseline to compare it with in the same group.
- Prefer wire assertions; add an endpoint assertion as corroboration, not instead.
- A scenario that is *supposed* to look bad (a downgrade) should still have every
  assertion pass - the assertions describe what the capture must show.
- Keep thresholds honest: calibrate them from a real capture and record the
  observed values in `expected_numbers`.
