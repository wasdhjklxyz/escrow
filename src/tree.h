#ifndef ESCROW_TREE_H
#define ESCROW_TREE_H

#include "proc.h"

// sha256 of a canonical serialization of the tree under dir: every entry
// (sorted by name, depth first) as its type, permission bits, relative
// path, and payload (file bytes, symlink target, or device number), plus
// user.* xattrs of files and dirs. Symlinks are never followed. Owner and
// timestamps are left out: apply can't reproduce them, and they don't
// change what a config means. Returns false (after a warning naming the
// entry) if anything can't be read, in which case the tree can't be
// pinned. Exits with status 1 on other failures.
bool tree_hash(const char *dir, char hex[SHA256_HEX + 1]);

#endif
