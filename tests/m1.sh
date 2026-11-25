#!/bin/sh
# M1 end-to-end: run tests/agent/m1.sh through escrow, check the diff, the
# exit status, and that the workspace is never touched. Needs a non-root
# user (root bypasses the 000 dirs the test relies on) and GNU find.
# usage: tests/m1.sh /abs/path/to/escrow
set -eu

escrow=${1:?usage: $0 /abs/path/to/escrow}
if [ "$(id -u)" -eq 0 ]; then
  echo "skip: run as a non-root user" >&2
  exit 0
fi
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'chmod -R u+rwx "$tmp"; rm -rf "$tmp"' EXIT
ws=$tmp/ws
state=$tmp/state
fails=0

check() {
  name=$1
  shift
  if "$@"; then
    echo "ok   $name"
  else
    echo "FAIL $name"
    fails=$((fails + 1))
  fi
}

snapshot() {
  (cd "$ws" && find . -printf '%P %m %s\n' | sort &&
    find . -type f -exec sha256sum {} + | sort)
}

mkdir -p "$ws/olddir" "$ws/replaced" "$ws/modedir" "$ws/locked"
for f in keep edit doomed noop; do echo "$f" >"$ws/$f.txt"; done
echo a >"$ws/olddir/a"
echo b >"$ws/olddir/b"
echo x >"$ws/replaced/x"
chmod 755 "$ws" "$ws/modedir"
before=$(snapshot)

cat >"$tmp/expected" <<'EOF'
M ./
A "a b"
A added.txt
A "backdoor\033[2K"
D doomed.txt
M edit.txt
A "evil\012D keep.txt"
A hidden/
A hidden/s
A link -> /etc/passwd
? locked/
? locked/z
M modedir/
A newdir/
A newdir/f
D olddir/
D olddir/a
D olddir/b
D replaced/x
A replaced/y
EOF

chmod 000 "$ws/locked"
st=0
"$escrow" --workspace "$ws" --state "$state" -- "$here/agent/m1.sh" \
  >"$tmp/out" || st=$?
chmod 755 "$ws/locked"
check "agent exit status 0 (got $st)" [ "$st" -eq 0 ]
check "diff output" diff -u "$tmp/expected" "$tmp/out"

run=$(echo "$state"/runs/*)
check "hidden upper dir mode restored" \
  [ "$(stat -c %a "$run/upper/hidden")" = 0 ]
sleep 2 # > the agent's background "sleep 1": late.txt would exist by now
check "leftover agent process killed" [ ! -e "$run/upper/late.txt" ]
check "workspace unchanged" [ "$(snapshot)" = "$before" ]

st=0
"$escrow" --workspace "$ws" --state "$state" -- sh -c 'exit 7' || st=$?
check "exit status passed through (got $st)" [ "$st" -eq 7 ]
st=0
"$escrow" --workspace "$ws" --state "$state" -- sh -c 'kill -TERM $$' ||
  st=$?
check "signal death is 128+sig (got $st)" [ "$st" -eq 143 ]

# SIGTERM to escrow kills the agent, not escrow: we still get the diff.
st=0
"$escrow" --workspace "$ws" --state "$state" -- \
  sh -c 'echo t >term.txt; sleep 5' >"$tmp/term.out" 2>/dev/null &
pid=$!
sleep 1
kill -TERM "$pid"
wait "$pid" || st=$?
check "SIGTERM kills the agent (got $st)" [ "$st" -eq 137 ]
check "SIGTERM still prints the diff" grep -qx 'A term.txt' "$tmp/term.out"

runs=$(ls "$state/runs" | wc -l)
st=0
"$escrow" --workspace "$ws/keep.txt" --state "$state" -- true 2>/dev/null ||
  st=$?
check "non-directory workspace refused" [ "$st" -eq 1 ]
check "refused run created no run dir" \
  [ "$(ls "$state/runs" | wc -l)" -eq "$runs" ]

st=0
"$escrow" --workspace "$ws" --state "$ws/state" -- true 2>"$tmp/err" || st=$?
check "state dir inside workspace refused" [ "$st" -ne 0 ]
check "refusal names the overlap" grep -q 'inside workspace' "$tmp/err"
check "refused run left workspace unchanged" [ "$(snapshot)" = "$before" ]

st=0
env -u ESCROW_STATE "$escrow" --workspace "$ws" -- true 2>/dev/null || st=$?
check "missing state dir refused" [ "$st" -eq 2 ]

[ "$fails" -eq 0 ]
