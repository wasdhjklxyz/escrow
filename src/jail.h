#ifndef ESCROW_JAIL_H
#define ESCROW_JAIL_H

struct run;

// Runs argv[0] with cwd at run->merged, in a forked child that enters a new
// user+mount ns and mounts the overlay. The caller never leaves the host
// namespaces. Returns the child's wait status (exit 125: setup failed,
// 127: exec failed) after killing and reaping every process left in the
// child's tree. In M1 that is the guarantee: the agent runs as our uid
// with the host fs visible, so it can still start a process outside its
// tree (systemd-run --user, a tmux server) that writes to upper/ later.
// M2's pid ns and pivot_root close that. Exits with status 1 on host-side
// failures.
int jail_run(const struct run *run, const char *ws, char *const argv[]);

#endif
