#!/bin/sh
# usage: write_outside.sh HOST_HOME NAME
# Tries $HOST_HOME/NAME. /tmp is the jail's own tmpfs, so writing it
# succeeds: the runner checks the host's /tmp/NAME never appears.
. "$(dirname "$0")/lib.sh"
try "write host \$HOME/$2" sh -c 'echo x >"$1/$2"' _ "$1" "$2"
echo x >"/tmp/$2"
exit $esc
