#!/bin/sh
# Harness: seed a workspace, run the malicious agent through escrow, capture the
# diff the signer would review. Shows raw bytes vs what a terminal renders.
set -eu
ESCROW=${1:?usage: $0 /abs/path/to/escrow POLICY}
POLICY=${2:?usage: $0 /abs/path/to/escrow POLICY}
# The jail sees only the role's store paths: run the agent from there.
HERE=$(sed -n 's/^env //p' "$POLICY")/share/escrow-tests/escape/poc
W=$(mktemp -d); S=$(mktemp -d)
trap 'rm -rf "$W" "$S"' EXIT

# authorized workspace content
printf 'make build\n' > "$W/deploy.sh"
printf '# changelog\n' > "$W/CHANGELOG.md"

# run the untrusted agent in the sandbox; capture the review diff (stdout)
"$ESCROW" --role "$POLICY" --workspace "$W" --state "$S" -- "$HERE/diff-spoof-agent.sh" > "$W/.diff.out" 2>/dev/null || true
OUT="$W/.diff.out"

echo "=================================================================="
echo "RAW diff bytes the supervisor produced (od -c):"
echo "=================================================================="
od -c "$OUT"

echo
echo "=================================================================="
echo "What the SIGNER sees on a terminal (interpreting the escapes):"
echo "=================================================================="
cat "$OUT"
echo "<<< end of terminal render"

echo
echo "=================================================================="
echo "What a LINE-BASED review tool / audit log scraper parses:"
echo "=================================================================="
nl -ba "$OUT"

echo
echo "=================================================================="
echo "GROUND TRUTH (the change set actually on disk in upper):"
echo "=================================================================="
find "$S"/runs/*/upper -mindepth 1 -printf '%y %P\n' | sort
