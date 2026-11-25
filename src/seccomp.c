#include "seccomp.h"

#include <err.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#if defined(__x86_64__)
#define ARCH AUDIT_ARCH_X86_64
#define SYSCALL_BIT_MASK 0x40000000 // __X32_SYSCALL_BIT
#elif defined(__aarch64__)
#define ARCH AUDIT_ARCH_AARCH64
#define SYSCALL_BIT_MASK 0
#else
#error "seccomp.c: add this architecture's AUDIT_ARCH"
#endif

// Low 32 bits of syscall argument n (little-endian; both arches above).
#define ARG(n) offsetof(struct seccomp_data, args[n])

#define LOAD(off) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (off))
#define JEQ(k, t, f) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (k), (t), (f))
#define RET(v) BPF_STMT(BPF_RET | BPF_K, (v))
#define ERRNO(e) RET(SECCOMP_RET_ERRNO | (e))

int seccomp_apply(void) {
  // Jump offsets count instructions skipped, so each block is laid out to
  // be read top to bottom: on a match it falls through, else it jumps on.
  struct sock_filter f[] = {
      LOAD(offsetof(struct seccomp_data, arch)),
      JEQ(ARCH, 1, 0),
      RET(SECCOMP_RET_KILL_PROCESS),
      LOAD(offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, SYSCALL_BIT_MASK, 0, 1),
      RET(SECCOMP_RET_KILL_PROCESS),

      // ENOSYS, so callers take their fallback path. io_uring makes sockets
      // without socket(2). memfd: execveat of one runs a native binary that
      // is in no store path. Keyrings: the inherited session keyring stays
      // readable by ID across user namespaces.
      JEQ(SYS_io_uring_setup, 7, 0),
      JEQ(SYS_io_uring_enter, 6, 0),
      JEQ(SYS_io_uring_register, 5, 0),
      JEQ(SYS_memfd_create, 4, 0),
      JEQ(SYS_memfd_secret, 3, 0),
      JEQ(SYS_keyctl, 2, 0),
      JEQ(SYS_add_key, 1, 0),
      JEQ(SYS_request_key, 0, 1),
      ERRNO(ENOSYS),
      JEQ(SYS_socket, 1, 0),
      RET(SECCOMP_RET_ALLOW),

      // socket(domain, type, protocol)
      LOAD(ARG(0)),
      JEQ(AF_UNIX, 0, 1),
      RET(SECCOMP_RET_ALLOW),
      JEQ(AF_INET, 1, 0),
      JEQ(AF_INET6, 0, 14), // neither: the final EACCES
      LOAD(ARG(1)),
      // Drop SOCK_NONBLOCK / SOCK_CLOEXEC, keep the type.
      BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf),
      JEQ(SOCK_STREAM, 0, 5),
      LOAD(ARG(2)),
      JEQ(0, 2, 0),
      JEQ(IPPROTO_TCP, 1, 0),
      ERRNO(EACCES),
      RET(SECCOMP_RET_ALLOW),
      JEQ(SOCK_DGRAM, 0, 5),
      LOAD(ARG(2)),
      JEQ(0, 2, 0),
      JEQ(IPPROTO_UDP, 1, 0),
      ERRNO(EACCES),
      RET(SECCOMP_RET_ALLOW),
      ERRNO(EACCES),
  };
  struct sock_fprog prog = {.len = sizeof f / sizeof *f, .filter = f};

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
    warn("prctl PR_SET_SECCOMP");
    return -1;
  }
  return 0;
}
