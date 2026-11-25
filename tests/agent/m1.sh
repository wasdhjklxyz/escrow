#!/bin/sh
# Cooperative M1 test agent. Runs with cwd at /work (the overlay) and
# makes one change of each kind that tests/m1.sh expects in the diff.
set -eu

chmod 750 . # workspace root is 755
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
chmod 700 locked # 000 in the workspace: the owner may still chmod it
echo z >locked/z
chmod 000 locked
mkdir hidden
echo s >hidden/s
chmod 000 hidden # escrow must still walk it, then restore the mode
ln -s /etc/passwd link
# Hostile names: must come out quoted, not as forged or erased lines.
: >'a b'
: >"$(printf 'evil\nD keep.txt')"
: >"$(printf 'backdoor\033[2K')"
# Outlives the agent. escrow must kill it before the diff.
sh -c 'sleep 1; echo late >late.txt' &
