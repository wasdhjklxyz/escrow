# The escape tour: escrow's own escape cases (tests/escape), run in the
# jail as a hostile agent and grouped by what answered them, then the limits
# a kernel jail does not close. escrow-web runs this with `bash -c` under
# role-test and no --key, so it proposes nothing; it prints to the agent
# log, which the page renders:
#   == <heading>|<what answered, and why>    a section
#   BLOCKED|ESCAPED|ERROR <attempt>: <first line of the error>   (lib.sh)
#   LIMIT <text>                             something the jail does not stop
# A case that exits non-zero without saying ESCAPED/ERROR (didn't run, died)
# prints ERROR here, and the tour exits 1.
# args: CASES HOME PWNED HOSTPID NSTORE (host facts the cases try to reach)
c=$1 home=$2 pwned=$3 pid=$4 nstore=$5
cd /work || exit 1
bad=0
case_() { # case_ NAME ARGS...: run one case; a silent failure is an ERROR
  out=$(sh "$c/$1.sh" "${@:2}" 2>&1)
  st=$?
  printf '%s\n' "$out"
  if [ "$st" -ne 0 ] && ! printf '%s\n' "$out" | grep -qE '^(ESCAPED|ERROR)'; then
    echo "ERROR case $1 did not run to the end: exit $st"
  fi
  [ "$st" -eq 0 ] || bad=1
}

echo "== Where the agent is|uid $(id -u); its whole / is: $(ls / | tr '\n' ' ')· $(ls /proc | grep -c '^[0-9]') processes visible"

echo "== Mount namespace + a root built from the role's Nix closure|the host's files don't exist in the agent's world, and escrow hands the agent an empty environment"
case_ read_secrets "$home"

echo "== Read-only root|outside /work and /tmp the jail's root is mounted read-only (Landlock, which allows writes only there, is the second wall)"
case_ write_outside "$home" "$pwned"

echo "== PID namespace|no host processes; /proc/1/root is refused by the kernel's ptrace access check (the jail's init keeps capabilities the agent doesn't have)"
case_ proc_escape "$pid" "$home"

echo "== Nix closure + noexec mounts|only the role's store paths are on PATH; /tmp and /work are mounted noexec, so a copied binary can't run (Landlock also withholds exec)"
case_ exec_undeclared "$nstore"

echo "== Network namespace + Landlock TCP rules|no interface but loopback, and Landlock refuses connect() to every TCP port (the Permission denied below)"
case_ net_none 22

echo "== No new namespaces|mount gives up in userspace without root (util-linux checks before the syscall); a nested user namespace fails because escrow set max_user_namespaces to 0 (ENOSPC)"
case_ mount_tricks

# The key is workspace content: never block on it (an applied FIFO), never
# print raw bytes (they would become lines this page parses).
k=$([ -f keys/api.key ] && [ ! -L keys/api.key ] && timeout 1 head -c 9 keys/api.key </dev/null | tr -cd '[:alnum:]-')
echo "== Limits|what this jail does not stop"
echo "LIMIT The agent reads everything in its workspace, secrets included (keys/api.key starts \"$k\"). Without network it can only put them in the diff, in front of the reviewer; with --net (the Claude tab) it could send them out over TCP 443."
echo "LIMIT seccomp blocks io_uring, memfd, keyrings and non-IP sockets, but no tool in this role can make those calls, so this tour can't show it."
echo "LIMIT escrow sets no CPU, memory or disk quotas; this server caps file size and systemd caps the rest."
echo "LIMIT A kernel bug in an allowed syscall is a way out. The next rung is a microVM per run."
exit $bad
