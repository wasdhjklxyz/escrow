#!/bin/sh
# Escape suite: run every tests/escape case through escrow as a hostile
# agent. A case passes only if every attempt it makes is BLOCKED, escrow
# exits 0, and the host is unchanged (workspace, host /tmp, $HOME/pwned).
# Needs a non-root user. The listener and pty cases skip without nc or
# script(1) on the host; the --net case skips below Landlock ABI 6.
# usage: tests/escape.sh /abs/path/to/escrow POLICY  (nix build .#role-test)
set -eu

escrow_bin=${1:?usage: $0 /abs/path/to/escrow POLICY}
policy=${2:?usage: $0 /abs/path/to/escrow POLICY}
if [ "$(id -u)" -eq 0 ]; then
  echo "skip: run as a non-root user" >&2
  exit 0
fi
cases=$(sed -n 's/^env //p' "$policy")/share/escrow-tests/escape
nstore=$(grep -c '^store ' "$policy")
tmp=$(mktemp -d)
listener=
trap 'chmod -R u+rwx "$tmp"; rm -rf "$tmp"; [ -z "$listener" ] || kill "$listener" 2>/dev/null' EXIT
ws=$tmp/ws
state=$tmp/state
pwned=escrow-pwned-$$
fails=0

mkdir "$ws"
echo original >"$ws/victim.txt"
snapshot() {
  (cd "$ws" && find . -printf '%P %m %s %l\n' | sort &&
    find . -type f -exec sha256sum {} + | sort)
}
before=$(snapshot)

# run CASE [escrow flags] -- [case args]: diff on $tmp/CASE.out, attempts
# on $tmp/CASE.err.
run() {
  name=$1
  shift
  flags=
  while [ "$1" != -- ]; do
    flags="$flags $1"
    shift
  done
  shift
  st=0
  # shellcheck disable=SC2086 # flags are fixed words from this file
  ESCAPE_SECRET=canary "$escrow_bin" --role "$policy" $flags \
    --workspace "$ws" --state "$state" -- "$cases/$name.sh" "$@" \
    >"$tmp/$name.out" 2>"$tmp/$name.err" || st=$?
  report "$name" "$st"
}

report() {
  if [ "$2" -eq 0 ] && ! grep -q '^ESCAPED' "$tmp/$1.err"; then
    echo "PASS $1"
  else
    echo "FAIL $1 (exit $2)"
    fails=$((fails + 1))
  fi
  grep -E '^(BLOCKED|ESCAPED)' "$tmp/$1.err" | sed 's/^/     /'
  grep -E '^escrow:' "$tmp/$1.err" | grep -v 'run dir' | sed 's/^/     /'
}

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

port=$(((($$ % 20000)) + 30000))
if command -v nc >/dev/null; then
  nc -lk 127.0.0.1 "$port" >/dev/null 2>&1 &
  listener=$!
  sleep 0.5
fi

run write_outside -- "$HOME" "$pwned"
check "host \$HOME/pwned absent" [ ! -e "$HOME/pwned" ]
check "host /tmp/$pwned absent" [ ! -e "/tmp/$pwned" ]
run read_secrets -- "$HOME"
if [ -n "$listener" ]; then
  run network -- "$port"
else
  echo "skip network: no nc on the host"
fi
run direct_workspace -- "$ws"
check "direct_workspace diff is M victim.txt" \
  grep -qx 'M victim.txt' "$tmp/direct_workspace.out"
run delete --
check "delete diff is D victim.txt" grep -qx 'D victim.txt' "$tmp/delete.out"
run exec_undeclared -- "$nstore"
run proc_escape -- "$$" "$HOME"
run mount_tricks --
run symlink -- "$HOME"
check "symlink diff shows targets" sh -c \
  'grep -qx "A etc-link -> /etc" "$1" && grep -qx "A home-link -> $2" "$1"' \
  _ "$tmp/symlink.out" "$HOME"

# fd 9 open on the host $HOME across exec of escrow.
st=0
ESCAPE_SECRET=canary "$escrow_bin" --role "$policy" --workspace "$ws" \
  --state "$state" -- "$cases/inherited_fd.sh" 9<"$HOME" \
  >"$tmp/inherited_fd.out" 2>"$tmp/inherited_fd.err" || st=$?
report inherited_fd "$st"

if command -v script >/dev/null; then
  st=0
  script -qec "\"$escrow_bin\" --role \"$policy\" --workspace \"$ws\" \
    --state \"$state\" -- \"$cases/tty.sh\" 2>\"$tmp/tty.err\"" /dev/null \
    >/dev/null || st=$?
  report tty "$st"
else
  echo "skip tty: no script(1) on the host"
fi

if [ -z "$listener" ]; then
  echo "skip net_443: no nc on the host"
elif ! "$escrow_bin" --role "$policy" --net --workspace "$ws" \
  --state "$state" -- true >/dev/null 2>&1; then
  echo "skip net_443: --net refused (Landlock ABI < 6?)"
else
  run net_443 --net -- "$port"
fi

check "workspace unchanged" [ "$(snapshot)" = "$before" ]
[ "$fails" -eq 0 ]
