#ifndef ESCROW_SECCOMP_H
#define ESCROW_SECCOMP_H

// Jail side, in the agent after PR_SET_NO_NEW_PRIVS. Installs a seccomp
// filter that closes what Landlock and the namespaces can't see:
//   - socket(): AF_UNIX, and AF_INET/AF_INET6 only as plain TCP
//     (SOCK_STREAM, protocol 0 or IPPROTO_TCP) or plain UDP (SOCK_DGRAM,
//     protocol 0 or IPPROTO_UDP). Landlock's TCP/UDP port rules don't
//     apply to MPTCP, SCTP, ICMP ping or raw sockets, so those get EACCES.
//   - ENOSYS: io_uring_* (creates sockets without socket(2)), memfd_create
//     and memfd_secret (execveat of a memfd runs a binary in no store
//     path), keyctl/add_key/request_key (the inherited session keyring).
//   - any other syscall ABI (x32, i386 on x86-64): the process is killed,
//     since the filter checks syscall numbers of this ABI only.
// Returns -1 after printing why. Never exits.
int seccomp_apply(void);

#endif
