#ifndef ESCROW_JAIL_H
#define ESCROW_JAIL_H

#include <sys/types.h>

#include "overlay.h"

/* Child exit codes for escrow's own failures (env(1) convention). */
enum {
  JAIL_ESETUP = 125,  /* namespace / mount setup failed */
  JAIL_ENOEXEC = 126, /* command found but not executable */
  JAIL_ENOENT = 127,  /* command not found */
};

/* Fork a child that enters a new user+mount ns, mounts the overlay and execs
 * argv in the merged dir. The parent stays in the host namespaces. */
pid_t jail_spawn(const struct overlay *ov, char *const argv[]);

/* Wait for the child; returns its exit status, or 128+sig if killed. */
int jail_wait(pid_t pid);

#endif
