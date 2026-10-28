# Notice

## Upstream: juliogomez/pqc

- Repository: https://github.com/juliogomez/pqc
- Licence: MIT
- Author: Julio Gomez (Cisco, Office of the CTO EMEA)
- Used as: git submodule at `vendor/juliogomez-pqc`. Its Dockerfiles and
  entrypoints under `learn/docker/` are built unmodified.
- Adapted (with attribution in each file header):
  `stacks/ipsec-auth/pki.sh`, `stacks/tls/tls-pki.sh`, `stacks/ssh/ssh-keys.sh`,
  `stacks/ssh/config/*`, `stacks/macsec/config/*`, and the swanctl configurations
  under `stacks/ipsec*/config/`.
- Pinned upstream commit: `49141a4b002b99ce336da3a7d6d6cac0bac91441` (2026-10-08,
  "Allow per-POD SAN overrides in the ML-DSA cert generator")

## Other components

- strongSwan, hostap (wpa_supplicant/hostapd), OpenSSH, OpenSSL, Wireshark/tshark:
  built or installed inside the upstream and agent images under their own licences.
- tecnativa/docker-socket-proxy (Apache-2.0).
- Fonts: Atkinson Hyperlegible Next and Mono (SIL Open Font License), loaded from Google Fonts.
