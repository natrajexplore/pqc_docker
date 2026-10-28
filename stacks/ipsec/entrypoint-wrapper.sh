#!/bin/bash
# PQC WireScope wrapper around the upstream strongSwan entrypoint.
#
# Upstream commits a throwaway PSK in swanctl.conf. We render the IKE PSK and the
# RFC 8784 post-quantum preshared key (PPK) from environment variables instead,
# into a root-only file under /run that never touches the repository. Every
# swanctl.conf / variant file pulls it in with:
#     include /run/pqcw/secrets.conf
#
# `make secrets` generates both values into .env with openssl rand.
set -euo pipefail

: "${PQCW_IKE_PSK:?PQCW_IKE_PSK is not set - run 'make secrets' first}"
: "${PQCW_IKE_PPK_HEX:?PQCW_IKE_PPK_HEX is not set - run 'make secrets' first}"

umask 077
mkdir -p /run/pqcw
cat > /run/pqcw/secrets.conf <<EOF
secrets {
    ike-psk {
        secret = "${PQCW_IKE_PSK}"
    }
    # RFC 8784 PPK, used only by the 'ppk' variant (ppk_id = pqcw-ppk).
    ppk-lab {
        id = pqcw-ppk
        secret = 0x${PQCW_IKE_PPK_HEX}
    }
}
EOF

# Hand over to the unmodified upstream entrypoint (starts charon, waits for VICI,
# runs swanctl --load-all, then waits on charon).
exec /entrypoint.sh "$@"
