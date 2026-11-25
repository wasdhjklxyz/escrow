#ifndef ESCROW_TREE_H
#define ESCROW_TREE_H

#include "proc.h"

// sha256 of a canonical serialization of the tree under dir (byte grammar
// in docs/FORMATS.md): every entry, depth first with names in strcmp
// order, as its type letter, mode & 07777 (set-id and sticky included),
// relative path, and payload (file bytes, symlink target, or st_rdev),
// plus user.* xattrs of files and dirs. Symlinks are never followed. Owner and
// timestamps are left out: apply can't reproduce them, and they don't
// change what a config means. Returns false (after a warning naming the
// entry) if anything can't be read, in which case the tree can't be
// pinned. Exits with status 1 on other failures.
bool tree_hash(const char *dir, char hex[SHA256_HEX + 1]);

// scandirat filter and order for walk order: no "." or "..", names by
// strcmp (not strcoll: the hash can't depend on the locale).
struct dirent;
int tree_skip_dots(const struct dirent *d);
int tree_by_name(const struct dirent **a, const struct dirent **b);

#endif
