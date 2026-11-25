#ifndef ESCROW_LANDLOCK_H
#define ESCROW_LANDLOCK_H

// The running kernel's Landlock ABI version, or 0 if Landlock is absent
// (not built in, or not in the lsm= list). Never exits.
int landlock_abi(void);

// Jail side, in the agent after pivot_root and PR_SET_NO_NEW_PRIVS. Allows
// only: read/exec under /nix/store, full access under /work and /tmp,
// read/write on the /dev nodes, read under /proc, listing dirs from /.
// TCP: bind denied, connect allowed only to port 443 when net is true and
// denied otherwise (ABI >= 4). ABI >= 6 also scopes abstract unix sockets
// and signals to the jail. abi is landlock_abi(): 0 warns and returns 0
// (the namespaces and pivot_root still contain the agent). Returns -1
// after printing why on any failure. Never exits.
int landlock_apply(int abi, bool net);

#endif
