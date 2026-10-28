#!/bin/bash
# Lab PKI for the IKEv2 authentication stack. Adapted from juliogomez/pqc
# learn/ipsec/authentication/gen-certs.sh (MIT), split into two verbs so the
# orchestrator can mint once and install per peer, with keys kept in the
# pqcw_ipsec_pki named volume instead of the git working tree.
#
#   pki.sh gen     <algo>          # run on ONE peer: CA + both leaf certs -> /pki/<algo>/
#   pki.sh install <algo> <peer>   # run on EACH peer: copy its set into swanctl dirs
#   pki.sh sizes   <algo>          # print DER sizes (cert, pubkey) as JSON for the UI
#
#   <algo>: ecdsa | ml-dsa-44 | ml-dsa-65 | ml-dsa-87
#   <peer>: initiator | responder
#
# LAB ONLY: keys are unencrypted, and the CA key sits in a volume both peers
# mount. Never reuse any of this outside the lab.
set -euo pipefail

VERB="${1:?usage: pki.sh gen|install|sizes <algo> [peer]}"
ALGO="${2:?algo required: ecdsa | ml-dsa-44 | ml-dsa-65 | ml-dsa-87}"
SWAN=/usr/local/etc/swanctl
DIR="/pki/${ALGO}"

case "$ALGO" in
  ecdsa)     GEN_OPTS=(--type ecdsa --size 256) ;;
  ml-dsa-44) GEN_OPTS=(--type mldsa44) ;;
  ml-dsa-65) GEN_OPTS=(--type mldsa65) ;;
  ml-dsa-87) GEN_OPTS=(--type mldsa87) ;;
  *) echo "unsupported algo '$ALGO'" >&2; exit 2 ;;
esac

gen() {
  # Idempotent: a re-run with the same algo reuses the existing CA so the
  # comparison between runs is apples to apples. Use FORCE=1 to re-mint.
  if [[ -f "$DIR/ca.crt" && "${FORCE:-0}" != "1" ]]; then
    echo ">> /pki/$ALGO already populated (FORCE=1 to re-mint)"; return 0
  fi
  umask 077
  rm -rf "$DIR"; mkdir -p "$DIR"; cd "$DIR"
  echo ">> CA ($ALGO)"
  pki --gen "${GEN_OPTS[@]}" --outform pem > ca.key
  pki --self --ca --lifetime 3650 --in ca.key --type priv \
      --dn "C=IN, O=PQC WireScope Lab, CN=PQC WireScope Lab CA" --outform pem > ca.crt
  for peer in initiator responder; do
    echo ">> leaf for $peer ($ALGO)"
    pki --gen "${GEN_OPTS[@]}" --outform pem > "$peer.key"
    pki --pub --in "$peer.key" --type priv --outform pem > "$peer.pub"
    pki --issue --lifetime 365 --cacert ca.crt --cakey ca.key \
        --in "$peer.pub" --type pub \
        --dn "C=IN, O=PQC WireScope Lab, CN=$peer.pqcw.lab" --san "$peer.pqcw.lab" \
        --flag serverAuth --flag clientAuth --outform pem > "$peer.crt"
  done
  chmod 0644 ca.crt initiator.crt responder.crt
  echo ">> done: $DIR"
}

install_peer() {
  local peer="${1:?peer required: initiator | responder}"
  [[ -f "$DIR/$peer.crt" ]] || { echo "no credentials for $ALGO yet - run 'pki.sh gen $ALGO' first" >&2; exit 3; }
  # Clear out whatever algorithm was installed before, so charon never holds a
  # stale key/CA pair from the previous run.
  rm -f "$SWAN"/private/* "$SWAN"/x509/* "$SWAN"/x509ca/*
  mkdir -p "$SWAN/private" "$SWAN/x509" "$SWAN/x509ca"
  install -m 0600 "$DIR/$peer.key" "$SWAN/private/$peer.key"
  install -m 0644 "$DIR/$peer.crt" "$SWAN/x509/$peer.crt"
  install -m 0644 "$DIR/ca.crt"    "$SWAN/x509ca/ca.crt"
  swanctl --load-all
  echo ">> installed $ALGO credentials for $peer"
}

sizes() {
  cd "$DIR"
  # PEM -> DER byte count with coreutils only (the strongSwan image has no openssl CLI).
  der() { sed '/-----/d' "$1" | base64 -d | wc -c; }
  local der_cert der_ca
  der_cert=$(der initiator.crt)
  der_ca=$(der ca.crt)
  printf '{"algo":"%s","leaf_cert_der_bytes":%s,"ca_cert_der_bytes":%s}\n' "$ALGO" "$der_cert" "$der_ca"
}

case "$VERB" in
  gen)     gen ;;
  install) install_peer "${3:-}" ;;
  sizes)   sizes ;;
  *) echo "unknown verb '$VERB'" >&2; exit 2 ;;
esac
