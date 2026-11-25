#ifndef ESCROW_OVERLAY_H
#define ESCROW_OVERLAY_H

#include <limits.h>

// One run's directories, all under <state>/runs/<id>. After the command
// exits, upper/ holds everything it changed: that is the change set.
struct run {
  char dir[PATH_MAX];
  char upper[PATH_MAX];
  char work[PATH_MAX];
  char merged[PATH_MAX];
};

// Host side, before fork. Creates <state>/runs/<id>/{upper,work,merged}
// (0700). Runs are kept after the run, and nothing deletes them yet
// (cleanup comes with M3's proposal lifecycle). Exits with status 1 if ws
// isn't a directory, if the state dir would land inside the workspace, or
// on any syscall failure. The checks run before anything is created, so a
// refused run leaves the workspace untouched. ws must be realpath() output.
void overlay_prepare(struct run *run, const char *state, const char *ws);

// Child side, inside the new user+mount ns. Mounts an overlay with ws as
// the read-only lower layer at run->merged. Returns 0, or -1 after printing
// why (including the kernel's fsconfig log). Never exits. Its fds are
// CLOEXEC and left open, so the caller must exec or _exit.
int overlay_mount(const struct run *run, const char *ws);

#endif
