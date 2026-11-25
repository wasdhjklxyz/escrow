#!/bin/sh
# usage: symlink.sh HOST_HOME
# apply doesn't exist until M3. For now the runner checks the diff shows the
# links with their targets and the walk didn't follow them.
ln -s /etc etc-link
ln -s "$1" home-link
