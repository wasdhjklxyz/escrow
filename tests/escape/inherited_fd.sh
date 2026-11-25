#!/bin/sh
# The runner starts escrow with fd 9 open on the host $HOME.
. "$(dirname "$0")/lib.sh"
try "inherited fd 9" ls /proc/self/fd/9/
exit $esc
