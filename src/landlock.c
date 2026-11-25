#include "landlock.h"

#include <err.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <sys/syscall.h>
#include <unistd.h>

// glibc has no wrappers for these.
static int create_ruleset(const struct landlock_ruleset_attr *attr, size_t size,
                          unsigned flags) {
  return (int)syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

static int add_rule(int ruleset, enum landlock_rule_type type,
                    const void *attr) {
  return (int)syscall(SYS_landlock_add_rule, ruleset, type, attr, 0);
}

static int restrict_self(int ruleset) {
  return (int)syscall(SYS_landlock_restrict_self, ruleset, 0);
}

int landlock_abi(void) {
  // ENOSYS (not built) or EOPNOTSUPP (built, not enabled at boot).
  int abi = create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
  return abi < 0 ? 0 : abi;
}

// Every fs right this ABI knows. Handling a right with no rule for it
// denies it, so handling all of them is what makes the rules an allowlist.
// Last checked against the ABI 11 header (Linux 7.3): a right added later
// is not handled, so it is allowed. Add it here when the header grows.
static __u64 fs_rights(int abi) {
  __u64 r = (LANDLOCK_ACCESS_FS_MAKE_SYM << 1) - 1; // ABI 1: bits 0..12
  if (abi >= 2)
    r |= LANDLOCK_ACCESS_FS_REFER;
  if (abi >= 3)
    r |= LANDLOCK_ACCESS_FS_TRUNCATE;
  if (abi >= 5)
    r |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
  if (abi >= 9)
    r |= LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
  return r;
}

static int allow_fd(int ruleset, int fd, const char *what, __u64 access) {
  struct landlock_path_beneath_attr pb = {.allowed_access = access,
                                          .parent_fd = fd};

  int r = add_rule(ruleset, LANDLOCK_RULE_PATH_BENEATH, &pb);
  if (r < 0)
    warn("landlock_add_rule %s", what);
  return r;
}

static int allow_path(int ruleset, const char *path, __u64 access) {
  int fd = open(path, O_PATH | O_CLOEXEC);
  if (fd < 0) {
    warn("open %s", path);
    return -1;
  }
  int r = allow_fd(ruleset, fd, path, access);
  close(fd);
  return r;
}

static int allow_port(int ruleset, __u64 access, __u64 port) {
  struct landlock_net_port_attr np = {.allowed_access = access, .port = port};

  int r = add_rule(ruleset, LANDLOCK_RULE_NET_PORT, &np);
  if (r < 0)
    warn("landlock_add_rule port %llu", (unsigned long long)port);
  return r;
}

int landlock_apply(int abi, bool net, int log) {
  const __u64 fs_all = fs_rights(abi);
  const __u64 ro = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
  // Rights a rule on a file (not a dir) may carry, minus exec.
  const __u64 rw_file =
      fs_all & (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
                LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV);
  // No EXECUTE: only store paths run, so the record's store hashes cover
  // every binary. The mounts are noexec too (ld.so mmap is not EXECUTE).
  const __u64 rw = fs_all & ~LANDLOCK_ACCESS_FS_EXECUTE;
  struct landlock_ruleset_attr attr = {.handled_access_fs = fs_all};

  if (abi < 1) {
    warnx("WARNING: Landlock unavailable; the agent runs without it "
          "(namespaces and pivot_root still apply)");
    return 0;
  }
  if (abi >= 4)
    attr.handled_access_net =
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
  if (abi >= 10)
    attr.handled_access_net |=
        LANDLOCK_ACCESS_NET_BIND_UDP | LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP;
  if (abi >= 6)
    attr.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;

  int ruleset = create_ruleset(&attr, sizeof attr, 0);
  if (ruleset < 0) {
    warn("landlock_create_ruleset");
    return -1;
  }
  int r = -1;
  // /dev is a read-only tmpfs holding only the binds build_root made, so
  // one rule on the dir covers exactly those nodes.
  if (allow_path(ruleset, "/", LANDLOCK_ACCESS_FS_READ_DIR) < 0 ||
      allow_path(ruleset, "/nix/store", ro | LANDLOCK_ACCESS_FS_EXECUTE) < 0 ||
      allow_path(ruleset, "/proc", ro) < 0 ||
      allow_path(ruleset, "/work", rw) < 0 ||
      allow_path(ruleset, "/tmp", rw) < 0 ||
      allow_path(ruleset, "/dev", rw_file) < 0 ||
      allow_fd(ruleset, log, "log", rw_file & ~LANDLOCK_ACCESS_FS_READ_FILE) <
          0)
    goto out;
  if (net) {
    // UDP rules need ABI 10; main refuses --net below that.
    if (allow_path(ruleset, "/etc/resolv.conf", LANDLOCK_ACCESS_FS_READ_FILE) <
            0 ||
        allow_port(ruleset, LANDLOCK_ACCESS_NET_CONNECT_TCP, 443) < 0 ||
        allow_port(ruleset, LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP, 53) < 0 ||
        allow_port(ruleset, LANDLOCK_ACCESS_NET_BIND_UDP, 0) < 0)
      goto out;
  }
  if ((r = restrict_self(ruleset)) < 0)
    warn("landlock_restrict_self");
out:
  close(ruleset);
  return r;
}
