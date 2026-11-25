#ifndef ESCROW_CHANGES_H
#define ESCROW_CHANGES_H

#include <limits.h>
#include <stdio.h>
#include <sys/types.h>

// The change set: the frozen, hashed form of a run's diff. Written once by
// the host-side diff walk from upper/, then read (never the upper dir
// again) by review, sign, apply and verify-log. Format:
//
//   "escrow-changes 1\n"
//   per entry:  "<op> <mode-octal> <pathlen> <datalen>\n" <path> <data>
//               ("x <namelen> <vallen>\n" <name> <value>)*  "e\n"
//
// ops: r (the workspace root: mode, xattrs; path empty), d (dir), f
// (regular file; data = bytes), l (symlink; data = target), p (fifo),
// D (delete path recursively). Paths are relative: components non-empty,
// never "." or "..", no leading, trailing or double '/'. Entries are
// strictly increasing in walk order (per-component strcmp, a dir before
// its children), so no path appears twice. Only user.* xattrs; no set-id
// bits, no sticky bit except on dirs. d/f/l/p replace whatever is at the
// path; D entries under an already deleted or replaced path are omitted.
// Integers are canonical (octal mode, decimal lengths, single spaces);
// limits: header line <= 80 bytes, path < PATH_MAX, xattr name <= 255,
// value <= XATTR_SIZE_MAX. Full spec: docs/FORMATS.md.

struct xattr {
  char *name;
  char *value;
  size_t len;
};

struct change {
  char op;
  mode_t mode; // permission bits only
  char *path;
  char *data;
  size_t len;
  struct xattr *x;
  size_t nx;
};

struct changeset {
  struct change *v;
  size_t n;
};

// Writer, fed by diff.c's emit(). Never fails the run: anything a change
// set can't carry marks it not proposable, with the reason in why.
struct changes_writer {
  FILE *f;
  bool ok;
  char why[PATH_MAX + 64];
  char covered[PATH_MAX]; // last deleted or replaced non-dir path, or ""
};

void changes_open(struct changes_writer *w, const char *file);
// One diff line: tag A/M/D/?, the entry's mode (type bits at least), its
// relative path ("" = root), and how to read it: the upper dir fd + name
// (for symlinks) and/or an open fd on the entry (files, dirs).
void changes_emit(struct changes_writer *w, char tag, mode_t mode,
                  const char *path, int dirfd, const char *name, int fd);
// Flushes and closes. Returns w->ok.
bool changes_close(struct changes_writer *w);

// Reader. Validates everything above; exits with status 1 naming the
// first problem. Free with changes_free().
void changes_read(const char *file, struct changeset *cs);

void changes_free(struct changeset *cs);

// Walk order of two relative paths: <0, 0, >0.
int changes_path_cmp(const char *a, const char *b);

#endif
