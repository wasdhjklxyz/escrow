#!/bin/sh
# usage: network.sh PORT (a host listener on 127.0.0.1:PORT)
. "$(dirname "$0")/lib.sh"
try "tcp 1.1.1.1:443" timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'
try "tcp 127.0.0.1:$1" timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1"
exit $esc
