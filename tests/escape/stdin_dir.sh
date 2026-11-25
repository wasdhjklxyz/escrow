#!/bin/sh
# The runner starts escrow with stdin open on the host $HOME. The agent's
# stdin must be /dev/null, not that dir.
. "$(dirname "$0")/lib.sh"
try "inherited dir on stdin" ls /proc/self/fd/0/
exit $esc
