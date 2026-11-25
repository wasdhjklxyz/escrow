#!/bin/sh
# Cooperative test agent: creates, edits and deletes files in its cwd.
set -eu

echo new > added.txt
echo more >> edit.txt
rm doomed.txt
: >> noop.txt # copy-up without a content change
mkdir newdir
echo hi > newdir/f
rm -rf olddir
rm -rf replaced # recreated below: an opaque dir
mkdir replaced
echo y > replaced/y
