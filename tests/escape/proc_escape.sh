#!/bin/sh
# usage: proc_escape.sh HOST_PID HOST_HOME (HOST_PID: the runner's pid)
. "$(dirname "$0")/lib.sh"
try "reach host fs via /proc/1/root" ls "/proc/1/root$2"
try "see host pid $1" test -d "/proc/$1"
try "see host pid 1 (systemd/init)" grep -qv escrow /proc/1/comm
exit $esc
