#!/bin/sh
# usage: net_443.sh PORT. Run with --net: the host net ns, where Landlock
# allows TCP connect to port 443 only.
. "$(dirname "$0")/lib.sh"
try "tcp 127.0.0.1:$1 under --net" \
  timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1"
exit $esc
