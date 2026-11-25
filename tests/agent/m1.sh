#!/bin/sh
# Cooperative M1 test agent. Runs with cwd at the merged overlay view and
# makes one change of each kind that tests/m1.sh expects in the diff.
set -eu

echo new >added.txt
echo more >>edit.txt
rm doomed.txt
: >>noop.txt # opened for writing, no change: copy-up only
mkdir newdir
echo hi >newdir/f
rm -rf olddir
rm -rf replaced # replaced/ comes back as an opaque dir
mkdir replaced
echo y >replaced/y
chmod 700 modedir
echo z >locked/z # locked/ is 000 in the workspace: root in the ns can write
mkdir hidden
echo s >hidden/s
chmod 000 hidden # escrow must still walk it, then restore the mode
# Outlives the agent. escrow must kill it before the diff.
sh -c 'sleep 1; echo late >late.txt' &
