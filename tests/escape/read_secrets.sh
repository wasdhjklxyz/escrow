#!/bin/sh
# usage: read_secrets.sh HOST_HOME
. "$(dirname "$0")/lib.sh"
for k in "$1"/.ssh/id_* "$1"/.ssh/authorized_keys; do
  try "read $k" sh -c 'head -c1 "$1" >/dev/null' _ "$k"
done
try "read /etc/shadow" sh -c 'head -c1 /etc/shadow >/dev/null'
try "list host \$HOME" ls "$1"
try "see host env (ESCAPE_SECRET)" sh -c '[ -n "${ESCAPE_SECRET-}" ]'
exit $esc
