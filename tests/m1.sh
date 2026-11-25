#!/bin/sh
# M1 end to end: run the test agent through escrow, check the printed diff
# and that the host workspace is untouched.
set -eu

escrow=${1:?usage: tests/m1.sh /abs/path/to/escrow}
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'chmod -R u+rwx "$tmp"; rm -rf "$tmp"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

snapshot() {
  (cd "$1" && find . -printf '%P %y %m %s\n' | sort &&
    find . -type f -exec sha256sum {} + | sort -k2)
}

ws=$tmp/ws
mkdir -p "$ws/olddir" "$ws/replaced"
for f in keep edit doomed noop; do echo "$f" > "$ws/$f.txt"; done
echo a > "$ws/olddir/a"
echo b > "$ws/olddir/b"
echo x > "$ws/replaced/x"
before=$(snapshot "$ws")

XDG_STATE_HOME=$tmp/state "$escrow" --workspace "$ws" -- \
  "$here/agent/m1.sh" > "$tmp/out" 2> "$tmp/err" || fail "escrow exited $?"
run=$(sed -n 's/^escrow: run //p' "$tmp/err")
[ -d "$run/upper" ] || fail "no run dir in: $(cat "$tmp/err")"

cat > "$tmp/want" << 'EOF'
A added.txt
D doomed.txt
M edit.txt
A locked/
A locked/s
A newdir/
A newdir/f
D olddir/
D olddir/a
D olddir/b
D replaced/x
A replaced/y
EOF
diff -u "$tmp/want" "$tmp/out" || fail "diff output"
[ "$before" = "$(snapshot "$ws")" ] || fail "host workspace changed"
echo "PASS: diff + host untouched"

[ "$(stat -c %a "$run/upper/locked")" = 0 ] || fail "locked mode not restored"
sleep 2
[ ! -e "$run/upper/late.txt" ] || fail "background writer outlived the agent"
echo "PASS: locked dir restored, leftovers killed"

if XDG_STATE_HOME=$ws/state "$escrow" --workspace "$ws" -- true \
  2> "$tmp/err"; then
  fail "state dir inside workspace accepted"
fi
grep -q 'is inside workspace' "$tmp/err" || fail "overlap error: $(cat "$tmp/err")"
[ "$before" = "$(snapshot "$ws")" ] || fail "overlap refusal touched workspace"
echo "PASS: overlap refused"
