#!/bin/sh
# usage: net_none.sh PORT (a host listener on 127.0.0.1:PORT)
# Default (no --net): an empty net ns. Landlock also denies TCP, so check
# the ns itself too: only lo may exist.
. "$(dirname "$0")/lib.sh"
try "tcp 1.1.1.1:443" timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'
try "tcp 127.0.0.1:$1" timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1"
try "see a network interface besides lo" \
  sh -c 'tail -n +3 /proc/net/dev | grep -qv "^ *lo:"'
exit $esc
