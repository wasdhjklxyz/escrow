#!/bin/sh
# M1 end-to-end: run tests/agent/m1.sh through escrow, check the diff, the
# exit status, and that the workspace is never touched. Needs a non-root
# user (escrow refuses root) and GNU find.
# usage: tests/m1.sh /abs/path/to/escrow POLICY  (POLICY: nix build .#role-test)
set -eu

escrow_bin=${1:?usage: $0 /abs/path/to/escrow POLICY}
policy=${2:?usage: $0 /abs/path/to/escrow POLICY}
escrow() { "$escrow_bin" --role "$policy" "$@"; }
# Inside the jail only the role's store paths exist: run the agent from there.
env=$(sed -n 's/^env //p' "$policy")
agent=$env/share/escrow-tests/agent/m1.sh
if [ "$(id -u)" -eq 0 ]; then
  echo "skip: run as a non-root user" >&2
  exit 0
fi
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
escrow --workspace "$ws" --state "$state" -- "$agent" \
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
escrow --workspace "$ws" --state "$state" -- sh -c 'exit 7' || st=$?
check "exit status passed through (got $st)" [ "$st" -eq 7 ]
st=0
escrow --workspace "$ws" --state "$state" -- sh -c 'kill -TERM $$' ||
  st=$?
check "signal death is 128+sig (got $st)" [ "$st" -eq 143 ]

# SIGTERM to escrow kills the agent, not escrow: we still get the diff.
# Not the escrow function: $! must be escrow itself.
st=0
"$escrow_bin" --role "$policy" --workspace "$ws" --state "$state" -- \
  sh -c 'echo t >term.txt; sleep 5' >"$tmp/term.out" 2>/dev/null &
pid=$!
sleep 1
kill -TERM "$pid"
wait "$pid" || st=$?
check "SIGTERM kills the agent (got $st)" [ "$st" -eq 137 ]
check "SIGTERM still prints the diff" grep -qx 'A term.txt' "$tmp/term.out"

# setcap/setfattr change no bytes or mode, so only xattrs reveal them.
if command -v setfattr >/dev/null; then
  escrow --workspace "$ws" --state "$state" -- sh -c \
    'setfattr -n user.note -v hi keep.txt; : >new.txt
     setfattr -n user.tag -v x new.txt' >"$tmp/xattr.out" 2>/dev/null
  check "xattr-only change is M" \
    grep -qx 'M keep.txt xattrs: user.note' "$tmp/xattr.out"
  check "added file lists its xattrs" \
    grep -qx 'A new.txt xattrs: user.tag' "$tmp/xattr.out"
else
  echo "skip xattr checks: setfattr not found"
fi

# $PWD must name /work, or $PWD-based writes hit the host.
escrow --workspace "$ws" --state "$state" -- \
  sh -c 'echo p >"$PWD/pwd.txt"' >"$tmp/pwd.out" 2>/dev/null
check "\$PWD write lands in the overlay" grep -qx 'A pwd.txt' "$tmp/pwd.out"
check "\$PWD write left workspace unchanged" [ "$(snapshot)" = "$before" ]

# More diff than a pipe holds, through head: SIGPIPE must not kill escrow
# with the locked dir still relaxed.
pstate=$tmp/pstate
escrow --workspace "$ws" --state "$pstate" -- sh -c \
  'mkdir L; i=0; while [ $i -lt 3000 ]; do : >L/a_longish_file_name_$i
   i=$((i + 1)); done; chmod 000 L' 2>/dev/null | head -n1 >/dev/null
prun=$(echo "$pstate"/runs/*)
check "closed stdout still restores modes" \
  [ "$(stat -c %a "$prun/upper/L")" = 0 ]

runs=$(ls "$state/runs" | wc -l)
st=0
escrow --workspace "$ws/keep.txt" --state "$state" -- true 2>/dev/null ||
  st=$?
check "non-directory workspace refused" [ "$st" -eq 1 ]
check "refused run created no run dir" \
  [ "$(ls "$state/runs" | wc -l)" -eq "$runs" ]

st=0
escrow --workspace "$ws" --state "$ws/state" -- true 2>"$tmp/err" || st=$?
check "state dir inside workspace refused" [ "$st" -ne 0 ]
check "refusal names the overlap" grep -q 'inside workspace' "$tmp/err"
check "refused run left workspace unchanged" [ "$(snapshot)" = "$before" ]

st=0
env -u ESCROW_STATE "$escrow_bin" --role "$policy" --workspace "$ws" -- true 2>/dev/null || st=$?
check "missing state dir refused" [ "$st" -eq 2 ]

st=0
"$escrow_bin" --workspace "$ws" --state "$state" -- true 2>/dev/null || st=$?
check "missing --role refused" [ "$st" -eq 2 ]
printf 'env %s\nstore /nix/store/../etc\n' "$env" >"$tmp/bad.policy"
st=0
"$escrow_bin" --role "$tmp/bad.policy" --workspace "$ws" --state "$state" \
  -- true 2>"$tmp/err" || st=$?
check "malformed policy refused" [ "$st" -eq 1 ]
check "refusal names the bad path" grep -q 'not a store path' "$tmp/err"

# --env NAME hands exactly that variable to the agent; others stay out.
estate=$tmp/estate
ESCROW_PASS=handed ESCROW_KEEP_OUT=leaked escrow --workspace "$ws" \
  --state "$estate" --env ESCROW_PASS -- sh -c \
  'printf %s "$ESCROW_PASS" >got; [ -z "${ESCROW_KEEP_OUT-}" ] && : >clean' \
  >"$tmp/env.out" 2>/dev/null
erun=$(echo "$estate"/runs/*)
check "--env: the named variable arrives" [ "$(cat "$erun/upper/got")" = handed ]
check "--env: other host variables stay out" [ -e "$erun/upper/clean" ]
st=0
escrow --workspace "$ws" --state "$estate" --env PATH -- true 2>/dev/null || st=$?
check "--env: reserved names refused" [ "$st" -eq 2 ]

[ "$fails" -eq 0 ]
