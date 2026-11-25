#!/bin/sh
# usage: write_outside.sh HOST_HOME TMP_NAME
# /tmp is the jail's own tmpfs, so writing it succeeds: the runner checks
# the host's /tmp/TMP_NAME never appears.
. "$(dirname "$0")/lib.sh"
try "write host \$HOME/pwned" sh -c 'echo x >"$1/pwned"' _ "$1"
echo x >"/tmp/$2"
exit $esc
