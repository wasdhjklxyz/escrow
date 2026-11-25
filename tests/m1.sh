#!/bin/sh
# M1 end-to-end: run tests/agent/m1.sh through escrow, check the diff, the
# exit status, and that the workspace is never touched.
# usage: tests/m1.sh /abs/path/to/escrow
set -eu

escrow=${1:?usage: $0 /abs/path/to/escrow}
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
chmod 755 "$ws/modedir"
before=$(snapshot)

expected='A added.txt
D doomed.txt
M edit.txt
A hidden/
A hidden/s
? locked/
? locked/z
M modedir/
A newdir/
A newdir/f
D olddir/
D olddir/a
D olddir/b
D replaced/x
A replaced/y'

chmod 000 "$ws/locked"
st=0
out=$("$escrow" --workspace "$ws" --state "$state" -- "$here/agent/m1.sh") ||
  st=$?
chmod 755 "$ws/locked"
check "agent exit status 0" [ "$st" -eq 0 ]
check "diff output" [ "$out" = "$expected" ]
[ "$out" = "$expected" ] ||
  printf '%s\n' "$out" | diff -u - /dev/fd/3 3<<EOF || true
$expected
EOF

run=$(echo "$state"/runs/*)
check "locked upper dir mode restored" [ "$(stat -c %a "$run/upper/hidden")" = 0 ]
sleep 2
check "leftover agent process killed" [ ! -e "$run/upper/late.txt" ]
check "workspace unchanged" [ "$(snapshot)" = "$before" ]

st=0
"$escrow" --workspace "$ws" --state "$state" -- sh -c 'exit 7' || st=$?
check "exit status passed through" [ "$st" -eq 7 ]
st=0
"$escrow" --workspace "$ws" --state "$state" -- sh -c 'kill -TERM $$' ||
  st=$?
check "signal death is 128+sig" [ "$st" -eq 143 ]

st=0
"$escrow" --workspace "$ws" --state "$ws/state" -- true 2>"$tmp/err" || st=$?
check "state dir inside workspace refused" [ "$st" -ne 0 ]
check "refusal names the overlap" grep -q 'inside workspace' "$tmp/err"
check "refused run left workspace unchanged" [ "$(snapshot)" = "$before" ]

st=0
env -u ESCROW_STATE "$escrow" --workspace "$ws" -- true 2>/dev/null || st=$?
check "missing state dir refused" [ "$st" -eq 2 ]

[ "$fails" -eq 0 ]
