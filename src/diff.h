#ifndef ESCROW_DIFF_H
#define ESCROW_DIFF_H

struct run;

// Prints what run->upper changes relative to the workspace ws, one line per
// entry on stdout, sorted by strcmp within each directory:
//
//   A|M|D|? <path>[/][ (fifo|socket|char|block|symlink)| -> <target>]
//
// '/' marks a dir and "./" is the workspace root. '?' means the entry could
// not be compared because the workspace side is unreadable. A path or
// symlink target holding a control byte, space, '"', '\' or non-ASCII byte
// is printed in double quotes, with '"' and '\' backslash-escaped and other
// unsafe bytes as octal ("a\012b"), so filenames can't forge or hide lines.
//
// M compares type, permission bits, size and bytes, symlink target and
// device numbers. It does not compare owner, timestamps or xattrs. ws must
// not itself contain overlay metadata (user.overlay.* xattrs, 0/0 char
// devices): the mount honors it but the walk reads it as plain files.
//
// Run from the host ns after every agent process is dead. Locked upper
// entries get u+r/u+rx for the walk and their modes are restored before
// return. Exits with status 1 on host-side errors. Call once per process
// (file-static state). Returns false if any '?' line was printed.
bool diff_print(const struct run *run, const char *ws);

#endif
