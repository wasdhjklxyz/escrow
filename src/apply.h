#ifndef ESCROW_APPLY_H
#define ESCROW_APPLY_H

struct changeset;

// Writes the change set into the tree at root, in order. Every path is
// resolved with openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
// RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV) from root, so no symlink or
// mount inside the tree can redirect a write or a delete outside it.
// d/f/l/p replace whatever is at the path (a dir in the way is removed
// recursively, never crossing a mount); f/l/p land via a temp name and
// renameat. Modes and user.* xattrs are set exactly (umask is ignored).
// Returns 0, or -1 after printing the path that failed; the tree may then
// be partly written, so callers apply to a staging copy. Never exits.
int apply_changes(const struct changeset *cs, const char *root);

#endif
