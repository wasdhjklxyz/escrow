#!/bin/sh
# usage: net_udp.sh PORT. Run with --net: UDP may only go to port 53.
# MPTCP/SCTP/ICMP sockets are seccomp's job; bash can't make those.
. "$(dirname "$0")/lib.sh"
try "udp 127.0.0.1:$1 under --net" \
  bash -c "echo exfil >/dev/udp/127.0.0.1/$1"
exit $esc
