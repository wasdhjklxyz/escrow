#ifndef ESCROW_OVERLAY_H
#define ESCROW_OVERLAY_H

#include <limits.h>

/* All paths are absolute and canonical. */
struct overlay {
  char lower[PATH_MAX];  /* the workspace, never written */
  char run[PATH_MAX];    /* per-run state dir */
  char upper[PATH_MAX];  /* run/upper: the change set */
  char work[PATH_MAX];   /* run/work: overlayfs scratch */
  char merged[PATH_MAX]; /* run/merged: mount point */
};

/* Parent, host ns. Resolves the workspace, creates the run dir, refuses
 * overlap between the two. Exits on failure. */
void overlay_prepare(struct overlay *ov, const char *workspace);

/* Child, inside the new user+mount ns. Mounts the overlay on ov->merged.
 * Returns -1 (context already printed) on failure. */
int overlay_mount(const struct overlay *ov);

#endif
