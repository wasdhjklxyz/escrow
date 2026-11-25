#ifndef ESCROW_APPLY_H
#define ESCROW_APPLY_H

struct changeset;

// openat2(root, path) with RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
// RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV: a symlink or a mount anywhere
// on the path, or a ".." that climbs out, makes it fail. "" means root.
// O_CLOEXEC is added. Returns the fd or -1 (errno set).
int open_beneath(int root, const char *path, int flags);

// Writes the change set into the tree at root, in order, every path
// resolved through open_beneath(). d/f/l/p replace whatever is at the path
// (a dir in the way is removed recursively, never crossing a mount). Modes
// and user.* xattrs are set exactly, whatever the umask; dir modes go on
// last, so a 0555 dir can still receive its children. Returns 0, or -1
// after printing the path that failed, leaving the tree partly written:
// callers apply to a staging copy. Never exits.
int apply_changes(const struct changeset *cs, const char *root);

#endif
