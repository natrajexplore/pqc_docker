#!/bin/sh
# Mint the SSH host key + lab user key into the pqcw_ssh_keys volume.
# Adapted from juliogomez/pqc learn/ssh/gen-keys.sh (MIT).
#
#   ssh-keys.sh <type>    type: ed25519 | mldsa44-ed25519
#
# Run on ssh-server (it mounts /keys read-write; the client mounts it read-only).
# The key exchange (mlkem768x25519-sha256) does not depend on the key type.
# LAB ONLY: keys are unencrypted.
set -eu

TYPE="${1:-ed25519}"
case "$TYPE" in
  ed25519|mldsa44-ed25519) : ;;
  *) echo "unsupported type '$TYPE' (ed25519 | mldsa44-ed25519)" >&2; exit 2 ;;
esac

WORK="$(mktemp -d)"; cd "$WORK"
ssh-keygen -q -t "$TYPE" -f ssh_host_key -N '' -C "pqcw ssh-server host key ($TYPE)"
ssh-keygen -q -t "$TYPE" -f id_key       -N '' -C "pqcw labuser ($TYPE)"

rm -rf /keys/server /keys/client
mkdir -p /keys/server /keys/client
chmod 0755 /keys /keys/server /keys/client

install -m 0600 ssh_host_key     /keys/server/ssh_host_key
install -m 0644 ssh_host_key.pub /keys/server/ssh_host_key.pub
install -m 0644 id_key.pub       /keys/server/authorized_keys   # sshd reads this as labuser

install -m 0600 id_key           /keys/client/id_key            # ssh runs as root in the client
install -m 0644 id_key.pub       /keys/client/id_key.pub
# Pin the host key by lab IP - the client connects to 172.33.0.2, not a name.
echo "172.33.0.2 $(cut -d' ' -f1-2 ssh_host_key.pub)" > /keys/client/known_hosts
chmod 0644 /keys/client/known_hosts

echo "$TYPE" > /keys/active_type
printf '{"type":"%s","host_pub_bytes":%s,"user_pub_bytes":%s}\n' "$TYPE" \
  "$(cut -d' ' -f2 ssh_host_key.pub | base64 -d | wc -c)" \
  "$(cut -d' ' -f2 id_key.pub | base64 -d | wc -c)"
rm -rf "$WORK"
