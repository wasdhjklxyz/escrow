#!/bin/sh
# usage: exec_undeclared.sh NSTORE (store paths in the role policy)
# Tools outside the role closure must not be reachable at all.
. "$(dirname "$0")/lib.sh"
for p in python3 nc curl perl; do
  try "reach $p" sh -c "command -v $p"
done
try "see store paths outside the policy" \
  sh -c '[ "$(ls /nix/store | wc -l)" -ne "$1" ]' _ "$1"
exit $esc
