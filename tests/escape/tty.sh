#!/bin/sh
# The runner starts escrow on a pty. A controlling tty would let the agent
# TIOCSTI keystrokes into the host terminal; a tty on stdin would let it
# read what the user types.
. "$(dirname "$0")/lib.sh"
try "have a controlling tty" sh -c '[ "$(cut -d" " -f7 /proc/self/stat)" != 0 ]'
try "have a tty on stdin" test -t 0
exit $esc
