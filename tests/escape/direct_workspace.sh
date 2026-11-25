#!/bin/sh
# usage: direct_workspace.sh HOST_WS
# Writing through /work is allowed (it lands in upper); the runner checks
# the host copy is untouched. Writing the real workspace path must fail.
. "$(dirname "$0")/lib.sh"
echo changed >victim.txt
try "write real workspace by abs path" sh -c 'echo x >"$1/victim.txt"' _ "$1"
exit $esc
