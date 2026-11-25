#!/bin/sh
# Escape suite: run every tests/escape case through escrow as a hostile
# agent. A case passes only if every attempt it makes is BLOCKED, escrow
# exits 0, and the host is unchanged (workspace, host /tmp, $HOME). The
# agent's reports land in the run log, not on escrow's stdout.
# Needs a non-root user. The listener and pty cases skip without nc or
# script(1) on the host; the --net cases skip below Landlock ABI 10.
# usage: tests/escape.sh /abs/path/to/escrow POLICY  (nix build .#role-test)
set -eu

escrow_bin=${1:?usage: $0 /abs/path/to/escrow POLICY}
policy=${2:?usage: $0 /abs/path/to/escrow POLICY}
if [ "$(id -u)" -eq 0 ]; then
  echo "skip: run as a non-root user" >&2
  exit 0
fi
escrow() { ESCAPE_SECRET=canary "$escrow_bin" --role "$policy" "$@"; }
cases=$(sed -n 's/^env //p' "$policy")/share/escrow-tests/escape
nstore=$(grep -c '^store ' "$policy")
tmp=$(mktemp -d)
listener=
trap 'chmod -R u+rwx "$tmp"; rm -rf "$tmp"
      [ -z "$listener" ] || kill "$listener" 2>/dev/null' EXIT
ws=$tmp/ws
state=$tmp/state
pwned=escrow-pwned-$$
fails=0

mkdir "$ws"
echo original >"$ws/victim.txt"
# %l: the symlink case must not leave links behind in the workspace.
snapshot() {
  (cd "$ws" && find . -printf '%P %m %s %l\n' | sort &&
    find . -type f -exec sha256sum {} + | sort)
}
before=$(snapshot)

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

# run CASE [escrow flags] -- [case args]: the diff on $tmp/CASE.out,
# escrow's stderr then the agent's log on $tmp/CASE.err. Redirections on
# the call (9<, 0<) reach escrow.
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
  escrow $flags --workspace "$ws" --state "$state" -- "$cases/$name.sh" "$@" \
    >"$tmp/$name.out" 2>"$tmp/$name.err" || st=$?
  report "$name" "$st"
}

# report CASE STATUS: appends the run's log to CASE.err, then judges it.
report() {
  log=$(sed -n 's/^escrow: agent output: //p' "$tmp/$1.err")
  [ -z "$log" ] || cat "$log" >>"$tmp/$1.err"
  if [ "$2" -eq 0 ] && ! grep -qE '^(ESCAPED|ERROR)' "$tmp/$1.err"; then
    echo "ok   $1"
  else
    echo "FAIL $1 (exit $2)"
    fails=$((fails + 1))
  fi
  grep -E '^(BLOCKED|ESCAPED|ERROR)' "$tmp/$1.err" | sed 's/^/     /'
  grep -E '^escrow:' "$tmp/$1.err" | grep -vE 'run dir|agent output' |
    sed 's/^/     /'
}

port=$(($$ % 20000 + 30000)) # unprivileged, below the ephemeral range
if command -v nc >/dev/null; then
  nc -lk 127.0.0.1 "$port" >/dev/null 2>&1 &
  listener=$!
  sleep 0.5
fi

run write_outside -- "$HOME" "$pwned"
check "host \$HOME/$pwned absent" [ ! -e "$HOME/$pwned" ]
check "host /tmp/$pwned absent" [ ! -e "/tmp/$pwned" ]
run read_secrets -- "$HOME"
if [ -n "$listener" ]; then
  run net_none -- "$port"
else
  echo "skip net_none: no nc on the host"
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
run inherited_fd -- 9<"$HOME"
run stdin_dir -- 0<"$HOME"
run stdout_forge --
check "stdout_forge: escrow's stdout is exactly the real diff" \
  [ "$(cat "$tmp/stdout_forge.out")" = "A real.txt" ]

if command -v script >/dev/null; then
  st=0
  script -qec "ESCAPE_SECRET=canary \"$escrow_bin\" --role \"$policy\" \
    --workspace \"$ws\" --state \"$state\" -- \"$cases/tty.sh\" \
    2>\"$tmp/tty.err\"" /dev/null >/dev/null || st=$?
  report tty "$st"
else
  echo "skip tty: no script(1) on the host"
fi

st=0
escrow --net --workspace "$ws" --state "$state" -- true \
  >/dev/null 2>"$tmp/net.err" || st=$?
if grep -q 'needs Landlock ABI' "$tmp/net.err"; then
  echo "skip --net cases: $(grep 'needs Landlock ABI' "$tmp/net.err")"
elif [ "$st" -ne 0 ]; then
  echo "FAIL --net setup (exit $st): $(grep -v 'run dir' "$tmp/net.err" | head -n1)"
  fails=$((fails + 1))
else
  if [ -n "$listener" ]; then
    run net_443 --net -- "$port"
  else
    echo "skip net_443: no nc on the host"
  fi
  run net_udp --net -- "$port"
  # The allowed side: DNS + TCP 443, if the host itself can get out.
  if timeout 5 bash -c 'exec 3<>/dev/tcp/example.com/443' 2>/dev/null; then
    net_ok() {
      escrow --net --workspace "$ws" --state "$state" -- bash -c \
        'timeout 5 bash -c "exec 3<>/dev/tcp/example.com/443"' \
        >/dev/null 2>&1
    }
    check "--net reaches example.com:443 by name" net_ok
  else
    echo "skip --net positive: the host has no route to example.com:443"
  fi
fi

check "workspace unchanged" [ "$(snapshot)" = "$before" ]
[ "$fails" -eq 0 ]
