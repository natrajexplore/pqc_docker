# PQC wire reference

What to look for in a capture, and the codepoints the analyzer uses. Mirrors
`backend/app/analyzer/codepoints.py`; change both together. Entries marked
**verify** are recent assignments - confirm against the IANA registry before
relying on them in a report.

## Sizes (bytes)

| Algorithm | Public / encapsulation key | Ciphertext / signature | Shared secret |
|---|---|---|---|
| X25519 | 32 | 32 | 32 |
| ML-KEM-512 | 800 | 768 | 32 |
| ML-KEM-768 | 1184 | 1088 | 32 |
| ML-KEM-1024 | 1568 | 1568 | 32 |
| ECDSA P-256 | 64 (+ encoding) | ~71 DER | - |
| ML-DSA-44 | 1312 | 2420 | - |
| ML-DSA-65 | 1952 | 3309 | - |
| ML-DSA-87 | 2592 | 4627 | - |

Hybrid TLS / SSH key shares: X25519MLKEM768 client share = 1184 + 32 = **1216**,
server share = 1088 + 32 = **1120**.

## IKEv2

| Item | Value | Source |
|---|---|---|
| Exchange IKE_SA_INIT / IKE_AUTH / CREATE_CHILD_SA / INFORMATIONAL | 34 / 35 / 36 / 37 | RFC 7296 |
| Exchange IKE_INTERMEDIATE | 43 | RFC 9242 |
| Exchange IKE_FOLLOWUP_KE | 44 | RFC 9370 |
| Payload SA / KE / Notify / SK / SKF | 33 / 34 / 41 / 46 / 53 | RFC 7296, RFC 7383 |
| Transform type 4 (Key Exchange Method) | 4 | RFC 9370 rename |
| Additional Key Exchange 1..7 | transform types 6..12 | RFC 9370 |
| KE method Curve25519 | 31 | RFC 8031 |
| KE method ML-KEM-512 / 768 / 1024 | 35 / 36 / 37 | **verify** (draft-ietf-ipsecme-ikev2-mlkem) |
| Notify IKEV2_FRAGMENTATION_SUPPORTED | 16430 | RFC 7383 |
| Notify SIGNATURE_HASH_ALGORITHMS | 16431 | RFC 7427 |
| Notify USE_PPK / PPK_IDENTITY / NO_PPK_AUTH | 16435 / 16436 / 16437 | **verify** (RFC 8784) |
| Notify INTERMEDIATE_EXCHANGE_SUPPORTED | 16438 | **verify** (RFC 9242) |

strongSwan proposal syntax: `aes256gcm16-prfsha256-x25519-ke1_mlkem768`;
`swanctl --list-sas` shows `.../CURVE_25519/KE1_ML_KEM_768`.

What a hybrid handshake looks like (upstream Part 4): IKE_SA_INIT req/resp
(X25519 + ADDKE1 offer), IKE_INTERMEDIATE req carrying the ML-KEM key (~1250 B,
2 fragments), IKE_INTERMEDIATE resp with the ciphertext (~1155 B), IKE_AUTH req/resp.

## TLS 1.3

| Item | Value |
|---|---|
| Group x25519 / secp256r1 | 0x001d / 0x0017 |
| MLKEM512 / MLKEM768 / MLKEM1024 | 0x0200 / 0x0201 / 0x0202 (**verify**, draft-ietf-tls-mlkem) |
| SecP256r1MLKEM768 / X25519MLKEM768 / SecP384r1MLKEM1024 | 0x11eb / 0x11ec / 0x11ed |
| SignatureScheme mldsa44 / mldsa65 / mldsa87 | 0x0904 / 0x0905 / 0x0906 (**verify**, draft-ietf-tls-mldsa) |
| X.509 OID ML-DSA-44 / 65 / 87 | 2.16.840.1.101.3.4.3.17 / .18 / .19 |

tshark: `tls.handshake.extensions_key_share_group == 0x11ec`.

## SSH

| Item | Value |
|---|---|
| KEXINIT / NEWKEYS / KEX_ECDH_INIT / KEX_ECDH_REPLY | 20 / 21 / 30 / 31 |
| Hybrid KEX names | `mlkem768x25519-sha256` (default since OpenSSH 10.0), `sntrup761x25519-sha512` |
| Composite key type | `mldsa44-ed25519` (ssh-keygen -t); algorithm name from `ssh -Q HostKeyAlgorithms` |

Negotiation rule (RFC 4253 section 7.1): the first algorithm on the client's
list that the server also supports. Both lists are in cleartext KEXINITs.

## 802.1X / EAP / MACsec

| Item | Value |
|---|---|
| EAPOL ethertype | 0x888e (PAE group address 01:80:c2:00:00:03) |
| MACsec ethertype | 0x88e5 |
| EAPOL type EAP-Packet / Start / MKA | 0 / 1 / 5 |
| EAP code Request / Response / Success / Failure | 1 / 2 / 3 / 4 |
| EAP type TLS | 13 |
| EAP-TLS flags L / M / S | 0x80 / 0x40 / 0x20 |

hostapd disables TLS 1.3 for EAP by default; `tls_flags=[ENABLE-TLSv1.3]` is
required, and wpa_supplicant needs `CONFIG_EAP_TLSV1_3=y` at build time.

## Cisco IOS XE 26.2 reality check (from upstream deploy docs)

- ML-KEM: IPsec, SSH, MACsec and the HTTPS server. ML-DSA: IKEv2 only.
- ML-DSA-65 IKEv2 auth on C8000: 7 frames / 7 KB -> 20 frames / 24 KB.
- PPK and ML-KEM are mutually exclusive on the same profile.
- Composite ML-DSA SSH keys: not supported (experimental IETF draft).
