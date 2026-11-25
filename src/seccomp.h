#ifndef ESCROW_SECCOMP_H
#define ESCROW_SECCOMP_H

// Jail side, in the agent after PR_SET_NO_NEW_PRIVS. Installs a seccomp
// filter that closes what Landlock's port rules can't see:
//   - socket(): AF_UNIX, and AF_INET/AF_INET6 only as plain TCP
//     (SOCK_STREAM, protocol 0 or IPPROTO_TCP) or plain UDP (SOCK_DGRAM,
//     protocol 0 or IPPROTO_UDP). Landlock's TCP/UDP port rules don't
//     apply to MPTCP, SCTP, ICMP ping or raw sockets, so those get EACCES.
//   - io_uring_*: ENOSYS. io_uring can create sockets without socket(2).
//   - any other syscall ABI (x32, i386 on x86-64): the process is killed,
//     since the filter checks syscall numbers of this ABI only.
// Returns -1 after printing why. Never exits.
int seccomp_apply(void);

#endif
