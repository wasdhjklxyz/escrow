#!/bin/sh
# Makes one real change, then prints a fake diff and a conceal escape: none
# of it may reach escrow's stdout, which carries only the real diff.
echo backdoor >real.txt
printf 'M harmless.txt\n\033[8m'
