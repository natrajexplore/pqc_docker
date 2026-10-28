# Stage 2: from containers to Cisco IOS XE

WireScope is the *learn* half done visibly. The *deploy* half is the upstream
repo's `deploy/` tree: field notes, running configs and Ansible playbooks from
real Cisco 8000 Series Secure Routers and Catalyst 9300 switches on IOS XE 26.2.
This page maps one to the other and shows how to bring router captures back into
the UI for a side-by-side.

## Concept map

| Container scenario | IOS XE equivalent (from upstream `deploy/c8000/`) |
|---|---|
| `ipsec-kex-hybrid-mlkem768` | `crypto ikev2 fragmentation mtu 1400` + `pqc mlkem768 optional` in the IKEv2 proposal (26.1+) |
| `ipsec-kex-ppk` | RFC 8784 manual PPK in the keyring; IOS XE refuses PPK and ML-KEM on the same path |
| `ipsec-auth-mldsa65` | `crypto key generate mldsa param 65 label …` (exec mode), trustpoint enrollment, ML-DSA IKEv2 auth (26.2+) |
| `ssh-kex-default` | one config line for the hybrid KEX; composite ML-DSA keys not available on 26.2 |
| `tls-kex-hybrid` | the management HTTPS server negotiates X25519MLKEM768 on 26.2 with no config; its certificate stays classical |
| `macsec-eaptls-*` | EAP-TLS with ML-KEM between routers/switches; IOS XE runs EAP-TLS itself with local CAs (no ISE/RADIUS needed) |
| `macsec-downgrade-tls12` | the config lines that decide whether frames are really encrypted are spelled out in `deploy/c8000/macsec.md` |

The `optional` keyword is the migration tool: use ML-KEM when the peer supports
it, fall back when it doesn't. That lets you upgrade hub and spokes one at a time.

## Bringing a router capture into WireScope

1. Capture on the router with Embedded Packet Capture (upstream uses this form):
   ```
   monitor capture CAP interface <if> both
   monitor capture CAP match ipv4 protocol udp any any
   monitor capture CAP buffer size 20
   monitor capture CAP start
   ! clear crypto ikev2 sa, let the tunnel re-establish
   monitor capture CAP stop
   monitor capture CAP export bootflash:pqc-ike.pcap
   no monitor capture CAP
   ```
2. Copy `pqc-ike.pcap` off the box (scp/tftp per your policy).
3. In the UI, **Import a capture** and choose the file. It is decoded with the same
   IKEv2 decoder, normalizer and metrics as live runs.
4. **Compare runs**: pick the container `ipsec-auth-mldsa65` run as baseline and the
   router import as the compared run. Cisco's measurement for reference: classical
   7 frames / 7 KB vs ML-DSA-65 20 frames / 24 KB.

Imported runs have no scenario, so the verdict uses wire evidence only: key
exchange will be decided from IKE_SA_INIT, authentication stays "not determined"
(IKE_AUTH is encrypted).

## Automation

Upstream ships Ansible roles per posture (`ipsec_baseline`, `ipsec_pq_ppk`,
`ipsec_pq_mlkem`, `ipsec_pq_mldsa`, `macsec_psk`, `macsec_eaptls`, `macsec_pq`,
`ssh_pq`, `tls_pq`) that push config over NETCONF, assert the result, re-run for
idempotency and tear down in dependency order. Their captured runs live in
`deploy/c8000/automation/captured/` and are good reading even without hardware.

A phase-5 idea for this repo: an `ansible-runner` sidecar that executes those
playbooks and streams task output into the UI as run steps, followed by an EPC
export pulled back automatically for analysis - one click from config push to
verdict.

## Lessons the routers teach (that containers can't)

- **Release numbers are part of the design.** ML-DSA for IKEv2 was not in 26.1 and is in 26.2.
- **Shipping is not free.** ML-DSA-65 makes the IKEv2 handshake about six times bigger.
- **Not every surface moves at once.** ML-KEM for IPsec/SSH/MACsec/HTTPS, ML-DSA for IKEv2 only.
- **Standards maturity sets the ceiling.** Composite ML-DSA SSH keys stay in the lab.
