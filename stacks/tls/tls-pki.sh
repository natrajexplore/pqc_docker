#!/bin/sh
# Lab PKI for the TLS and MACsec (EAP-TLS) stacks, using OpenSSL 3.5's default
# provider. Adapted from juliogomez/pqc learn/tls/authentication/gen-certs.sh
# (MIT). Keys live in a named volume mounted at /pki, never in the repo.
#
#   tls-pki.sh gen      <algo>   # CA + server + client leaf certs -> /pki/<algo>/
#   tls-pki.sh activate <algo>   # point /pki/active -> /pki/<algo> (what configs reference)
#   tls-pki.sh sizes    <algo>   # DER sizes as JSON, for the UI's size table
#
#   <algo>: ecdsa | ml-dsa-44 | ml-dsa-65 | ml-dsa-87
#
# Leaf names: server.pqcw.lab (serverAuth) and client.pqcw.lab (clientAuth).
# LAB ONLY: unencrypted keys. FORCE=1 re-mints an existing set.
set -eu

VERB="${1:?usage: tls-pki.sh gen|activate|sizes <algo>}"
ALGO="${2:?algo required}"
DIR="/pki/$ALGO"

case "$ALGO" in
  ecdsa)     KEYGEN="openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256" ;;
  ml-dsa-44) KEYGEN="openssl genpkey -algorithm ML-DSA-44" ;;
  ml-dsa-65) KEYGEN="openssl genpkey -algorithm ML-DSA-65" ;;
  ml-dsa-87) KEYGEN="openssl genpkey -algorithm ML-DSA-87" ;;
  *) echo "unsupported algo '$ALGO'" >&2; exit 2 ;;
esac

issue() {
  name="$1"; cn="$2"; eku="$3"
  $KEYGEN -out "$name.key"
  openssl req -new -key "$name.key" -out "$name.csr" -subj "/C=IN/O=PQC WireScope Lab/CN=$cn"
  printf 'extendedKeyUsage=%s\nsubjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n' "$eku" "$cn" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
      -out "$name.crt" -days 365 -extfile "$name.ext" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
}

gen() {
  if [ -f "$DIR/ca.crt" ] && [ "${FORCE:-0}" != "1" ]; then
    echo ">> $DIR already populated (FORCE=1 to re-mint)"; return 0
  fi
  echo ">> $(openssl version)"
  umask 077
  rm -rf "$DIR"; mkdir -p "$DIR"; cd "$DIR"
  $KEYGEN -out ca.key
  openssl req -x509 -new -key ca.key -out ca.crt -days 3650 \
      -subj "/C=IN/O=PQC WireScope Lab/CN=PQC WireScope Lab CA"
  issue server server.pqcw.lab serverAuth
  issue client client.pqcw.lab clientAuth
  # Certs world-readable, keys stay 0600.
  chmod 0644 ca.crt server.crt client.crt
  chmod 0755 "$DIR"
  echo ">> done: $DIR"
}

activate() {
  [ -f "$DIR/server.crt" ] || { echo "run 'tls-pki.sh gen $ALGO' first" >&2; exit 3; }
  ln -sfn "$DIR" /pki/active
  echo ">> /pki/active -> $DIR"
}

sizes() {
  cd "$DIR"
  leaf=$(openssl x509 -in server.crt -outform der | wc -c)
  ca=$(openssl x509 -in ca.crt -outform der | wc -c)
  pub=$(openssl pkey -in server.key -pubout -outform der | wc -c)
  printf '{"algo":"%s","leaf_cert_der_bytes":%s,"ca_cert_der_bytes":%s,"leaf_pubkey_der_bytes":%s}\n' \
    "$ALGO" "$leaf" "$ca" "$pub"
}

case "$VERB" in
  gen) gen ;;
  activate) activate ;;
  sizes) sizes ;;
  *) echo "unknown verb '$VERB'" >&2; exit 2 ;;
esac
