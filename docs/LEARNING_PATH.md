# Learning path: from "what is ML-KEM" to deploying it on routers

Four weeks at roughly an hour a day. Each week pairs the upstream lab (by hand,
to learn), the matching WireScope scenarios (automated, to see and measure),
and one thing to write down in your own words.

Sources:
- Upstream labs: https://github.com/juliogomez/pqc (`learn/` then `deploy/`)
- Cisco blog series by Julio Gomez, "IPsec Series" Parts 1-11: https://blogs.cisco.com/author/juliogomez
- Cisco DevNet live stream Ep. 120, *Post-Quantum Cryptography in the Real World*:
  https://www.youtube.com/live/9v_nuDHSd5I
- Standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), RFC 9370, RFC 9242, RFC 7383, RFC 8784

## Week 1 - The two pillars, and IPsec key exchange

| Do | Where |
|---|---|
| Read "the challenge" and IPsec Parts 1-3 | upstream README, Cisco blogs |
| Run `learn/ipsec/key-exchange` by hand, capture with tcpdump | upstream |
| Run `ipsec-kex-classical`, then `ipsec-kex-hybrid-mlkem768`, then compare | WireScope |
| Run `ipsec-kex-hybrid-mlkem1024` and `ipsec-kex-ppk` | WireScope |

Write down: why key exchange is the urgent pillar (harvest now, decrypt later);
why IKEv2 needs an extra round trip (IKE_INTERMEDIATE) and fragmentation for
ML-KEM-768; when PPK is a reasonable bridge and why IOS XE refuses PPK + ML-KEM together.

Optional depth: `learn/module-lattices` (toy LWE, baby Kyber, a real lattice attack).

## Week 2 - Authentication and the certificate size explosion

| Do | Where |
|---|---|
| IPsec Parts 6-8 | Cisco blogs |
| Run `learn/ipsec/authentication` (ECDSA then ML-DSA) | upstream |
| Run `ipsec-auth-ecdsa`, `ipsec-auth-mldsa44`, `ipsec-auth-mldsa65`; compare | WireScope |
| Run `learn/tls/authentication`, then `tls-auth-ecdsa-mtls` vs `tls-auth-mldsa65-mtls` | both |

Write down: ML-DSA-44/65/87 key and signature sizes; why the authentication
deadline is "certificates must outlive the CRQC" rather than retroactive; what
the decrypted TLS Certificate shows (OIDs 2.16.840.1.101.3.4.3.17/18/19).

## Week 3 - TLS, SSH and MACsec

| Do | Where |
|---|---|
| `learn/tls/key-exchange`; `tls-kex-classical` vs `tls-kex-hybrid` | both |
| `learn/ssh`; `ssh-kex-default`, `ssh-kex-downgrade`, `ssh-auth-composite` | both |
| `learn/macsec`; all four `macsec-*` scenarios | both |

Write down: why TLS and SSH need no extra round trip; the difference between a
**silent** downgrade (EAP-TLS, hostapd without `tls_flags`) and a **loud** one
(SSH warns; a TLS-1.3-pinned supplicant fails closed); MACsec's key hierarchy
MSK -> CAK -> SAK and why the data plane (AES-GCM) is not the problem.

## Week 4 - Deploy on Cisco hardware (or read it)

| Do | Where |
|---|---|
| Watch DevNet Ep. 120 router half: one-line ML-KEM, ML-DSA key on the box, EPC, Ansible over NETCONF | YouTube |
| Read `deploy/c8000/{ipsec,ssh,tls,macsec}.md` and the captured evidence logs | upstream |
| IPsec Parts 9-11 (routers, ML-DSA certs, the honest migration playbook) | Cisco blogs |
| Import an EPC capture into WireScope and compare it with the container run | WireScope |

Write down your migration plan for a real network: inventory -> PQ key exchange
first (IPsec ML-KEM, SSH, TLS) -> MACsec EAP-TLS 1.3 everywhere (and pin it) ->
ML-DSA auth where the release supports it, with outage windows planned for the
handshake size change. Include release numbers, not just algorithm names
(IOS XE 26.2 is where ML-DSA for IKEv2 arrived).

## Interview-ready summary (one breath each)

- **ML-KEM** (FIPS 203): lattice KEM replacing (EC)DH; deployed hybrid with X25519.
- **ML-DSA** (FIPS 204): lattice signatures replacing RSA/ECDSA; big keys and signatures.
- **IKEv2**: RFC 9370 ADDKE + RFC 9242 IKE_INTERMEDIATE + RFC 7383 fragmentation; one extra RTT.
- **TLS 1.3**: X25519MLKEM768 (0x11ec) in the same hellos; zero extra RTT.
- **SSH**: mlkem768x25519-sha256 default since OpenSSH 10.0; recent releases warn on a non-PQ KEX.
- **MACsec**: quantum exposure is EAP-TLS; enable and pin TLS 1.3 or it silently drops to 1.2.
