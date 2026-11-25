#ifndef ESCROW_JAIL_H
#define ESCROW_JAIL_H

struct run;
struct policy;

// What the agent gets. ws must be realpath() output.
struct jail {
  const struct run *run;
  const char *ws;
  const struct policy *policy;
  bool net;         // host net ns: TCP 443, DNS (UDP 53), resolv.conf
  int landlock_abi; // landlock_abi()
};

// Runs argv[0] (looked up in the role's env/bin) in a jail: clone3 into a
// new user, mount, pid and (unless j->net) net ns. The child is PID 1, our
// own init: it builds a root of the policy's store paths, the overlay at
// /work, tmpfs /tmp, minimal /dev and a fresh /proc, pivots into it, then
// forks the agent with no caps, a clean env, no controlling tty, Landlock
// and seccomp. The agent's stdin is /dev/null and its stdout + stderr go
// to run->log, never to escrow's stdout, which carries only the diff.
// The caller never leaves the host namespaces. Returns init's wait
// status: init exits with the agent's status (128+N if the agent was
// killed by signal N), 125 if setup failed, 127 if exec failed (an agent
// that itself exits 125 or 127 looks the same). When it returns, every
// jailed process is dead: init's exit kills the pid ns and doesn't
// complete until the ns is empty. Exits with status 1 on host-side
// failures.
int jail_run(const struct jail *j, char *const argv[]);

#endif
