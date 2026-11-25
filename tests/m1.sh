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

"$escrow" --state "$tmp/state" --workspace "$ws" -- \
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

# A workspace dir the host user can't read (the agent can, via
# CAP_DAC_OVERRIDE in its userns), and a mode change on an existing dir.
ws2=$tmp/ws2
mkdir -p "$ws2/sec" "$ws2/open"
chmod 000 "$ws2/sec"
"$escrow" --state "$tmp/state" --workspace "$ws2" -- \
  sh -c 'echo n > sec/new && chmod 777 open' > "$tmp/out2" 2> "$tmp/err2" ||
  fail "escrow exited $? on unreadable lower: $(cat "$tmp/err2")"
run2=$(sed -n 's/^escrow: run //p' "$tmp/err2")
printf 'M open/\n? sec/\nA sec/new\n' | diff -u - "$tmp/out2" ||
  fail "unreadable-lower diff"
[ "$(stat -c %a "$run2/upper/sec")" = 0 ] || fail "upper sec mode not restored"
[ "$(stat -c %a "$ws2/sec")" = 0 ] || fail "workspace sec mode changed"
echo "PASS: unreadable lower marked, dir mode change reported"

if "$escrow" --state "$ws/state" --workspace "$ws" -- true \
  2> "$tmp/err"; then
  fail "state dir inside workspace accepted"
fi
grep -q 'is inside workspace' "$tmp/err" || fail "overlap error: $(cat "$tmp/err")"
[ "$before" = "$(snapshot "$ws")" ] || fail "overlap refusal touched workspace"
echo "PASS: overlap refused"

if env -u ESCROW_STATE "$escrow" --workspace "$ws" -- true 2> "$tmp/err"; then
  fail "missing state dir accepted"
fi
grep -q 'no state dir' "$tmp/err" || fail "no-state error: $(cat "$tmp/err")"
echo "PASS: state dir required"
