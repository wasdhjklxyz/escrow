#!/bin/sh
# The runner starts escrow on a pty. A controlling tty would let the agent
# TIOCSTI keystrokes into the host terminal.
. "$(dirname "$0")/lib.sh"
try "have a controlling tty" sh -c '[ "$(cut -d" " -f7 /proc/self/stat)" != 0 ]'
exit $esc
