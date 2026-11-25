#!/bin/sh
# usage: exec_undeclared.sh NSTORE (store paths in the role policy)
# Tools outside the role closure must not be reachable or runnable: not
# on PATH, not elsewhere in /nix/store, not copied into /work or /tmp.
. "$(dirname "$0")/lib.sh"
for p in python3 nc curl perl; do
  try "reach $p" sh -c "command -v $p"
done
try "see store paths outside the policy" \
  sh -c '[ "$(ls /nix/store | wc -l)" -ne "$1" ]' _ "$1"
ls=$(readlink -f "$(command -v ls)")
cp "$ls" /tmp/copied
try "exec a binary copied to /tmp" /tmp/copied /
cp "$ls" ./copied
try "exec a binary copied to /work" ./copied /
rm -f ./copied
exit $esc
