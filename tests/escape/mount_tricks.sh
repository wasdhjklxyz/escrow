#!/bin/sh
# The agent has no caps and Landlock forbids mount topology changes. Note:
# util-linux refuses mount/umount in userspace before the syscall.
. "$(dirname "$0")/lib.sh"
d=$(mktemp -d)
try "mount tmpfs" mount -t tmpfs none "$d"
try "umount /work" sh -c 'cd / && umount -n /work'
try "remount / rw" mount -o remount,rw /
try "unshare again" unshare -r true
exit $esc
