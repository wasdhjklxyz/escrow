#ifndef ESCROW_JAIL_H
#define ESCROW_JAIL_H

struct run;

// Exit code of a child that failed before exec (ns or overlay setup).
// 125 is the usual "the wrapper failed" code (env, chroot, timeout).
enum { JAIL_SETUP_FAILED = 125 };

// Runs argv[0] with cwd at run->merged, in a forked child that enters a new
// user+mount ns and mounts the overlay. The caller never leaves the host
// namespaces. Returns the child's wait status after killing and reaping
// any processes it left behind, so nothing writes to upper/ after return.
int jail_run(const struct run *run, const char *ws, char *const argv[]);

#endif
