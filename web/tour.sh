# The escape tour: escrow's own escape cases (tests/escape), run in the
# jail as a hostile agent and grouped by the layer that should stop them,
# then the limits a kernel jail does not close. escrow-web runs this with
# `bash -c` under role-test and no --key, so it proposes nothing; it prints
# to the agent log, which the page renders:
#   == <layer>|<what it means>     a section
#   BLOCKED|ESCAPED|ERROR <attempt>: <first line of the error>   (lib.sh)
#   LIMIT <text>                   something the jail does not stop
# args: CASES HOME PWNED HOSTPID NSTORE (host facts the cases try to reach)
c=$1 home=$2 pwned=$3 pid=$4 nstore=$5
cd /work || exit 1

echo "== Where the agent is|uid $(id -u); its whole / is: $(ls / | tr '\n' ' ')· $(ls /proc | grep -c '^[0-9]') processes visible"

echo "== Mount namespace + a root built from the role's Nix closure|the host's files are not in the agent's world"
sh "$c/read_secrets.sh" "$home" 2>&1

echo "== Landlock|writes allowed only under /work and /tmp, and the overlay keeps /work's writes out of the real workspace"
sh "$c/write_outside.sh" "$home" "$pwned" 2>&1

echo "== PID namespace|no host processes, and /proc/1/root is the jail's own root"
sh "$c/proc_escape.sh" "$pid" "$home" 2>&1

echo "== Nix closure + Landlock without exec|only the role's store paths run; a copied binary can't"
sh "$c/exec_undeclared.sh" "$nstore" 2>&1

echo "== Network namespace + Landlock TCP rules|no interface but loopback, and Landlock refuses connect() to every TCP port (the Permission denied below)"
sh "$c/net_none.sh" 22 2>&1

echo "== User namespace without capabilities|mount gives up in userspace without root (util-linux checks before the syscall); the kernel refuses a nested user namespace (ENOSPC)"
sh "$c/mount_tricks.sh" 2>&1

echo "== Limits|what this jail does not stop"
echo "LIMIT The agent reads everything in its workspace, secrets included (keys/api.key starts \"$(head -c 9 keys/api.key)\"). Without network it can only put them in the diff, in front of the reviewer; with --net (the Claude tab) it could send them out over TCP 443."
echo "LIMIT seccomp blocks io_uring, memfd, keyrings and non-IP sockets, but no tool in this role can make those calls, so this tour can't show it."
echo "LIMIT escrow sets no CPU, memory or disk quotas; this server caps file size and systemd caps the rest."
echo "LIMIT A kernel bug in an allowed syscall is a way out. The next rung is a microVM per run."
exit 0
