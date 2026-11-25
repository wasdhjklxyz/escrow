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

static int add_rule(int fd, enum landlock_rule_type type, const void *attr) {
  return (int)syscall(SYS_landlock_add_rule, fd, type, attr, 0);
}

int landlock_abi(void) {
  // ENOSYS (not built) or EOPNOTSUPP (built, not enabled at boot).
  int abi = create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
  return abi < 0 ? 0 : abi;
}

// Every fs right this ABI knows. Handling a right with no rule for it
// denies it, so handling all of them is what makes the rules an allowlist.
static __u64 fs_rights(int abi) {
  __u64 r = (LANDLOCK_ACCESS_FS_MAKE_SYM << 1) - 1; // ABI 1: bits 0..12
  if (abi >= 2)
    r |= LANDLOCK_ACCESS_FS_REFER;
  if (abi >= 3)
    r |= LANDLOCK_ACCESS_FS_TRUNCATE;
  if (abi >= 5)
    r |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
  return r;
}

static int allow_path(int ruleset, const char *path, __u64 access) {
  struct landlock_path_beneath_attr pb = {.allowed_access = access};

  pb.parent_fd = open(path, O_PATH | O_CLOEXEC);
  if (pb.parent_fd < 0) {
    warn("landlock: open %s", path);
    return -1;
  }
  int r = add_rule(ruleset, LANDLOCK_RULE_PATH_BENEATH, &pb);
  if (r < 0)
    warn("landlock: add rule %s", path);
  close(pb.parent_fd);
  return r;
}

int landlock_apply(int abi, bool net) {
  static const char *const devs[] = {"/dev/null", "/dev/zero", "/dev/full",
                                     "/dev/random", "/dev/urandom"};
  const __u64 all = fs_rights(abi);
  // The only rights a rule on a non-directory may carry.
  const __u64 file =
      all & (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
             LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |
             LANDLOCK_ACCESS_FS_IOCTL_DEV);
  const __u64 ro = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
  struct landlock_ruleset_attr attr = {.handled_access_fs = all};
  struct landlock_net_port_attr https = {
      .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP, .port = 443};

  if (abi < 1) {
    warnx("WARNING: Landlock unavailable; the agent runs without it "
          "(namespaces and pivot_root still apply)");
    return 0;
  }
  if (abi >= 4)
    attr.handled_access_net =
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
  if (abi >= 6)
    attr.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;

  int fd = create_ruleset(&attr, sizeof attr, 0);
  if (fd < 0) {
    warn("landlock_create_ruleset");
    return -1;
  }
  int r = -1;
  if (allow_path(fd, "/", LANDLOCK_ACCESS_FS_READ_DIR) < 0 ||
      allow_path(fd, "/nix/store", ro | LANDLOCK_ACCESS_FS_EXECUTE) < 0 ||
      allow_path(fd, "/proc", ro) < 0 || allow_path(fd, "/work", all) < 0 ||
      allow_path(fd, "/tmp", all) < 0)
    goto out;
  for (size_t i = 0; i < sizeof devs / sizeof *devs; i++)
    if (allow_path(fd, devs[i], file & ~LANDLOCK_ACCESS_FS_EXECUTE) < 0)
      goto out;
  if (net && add_rule(fd, LANDLOCK_RULE_NET_PORT, &https) < 0) {
    warn("landlock: add rule tcp/443");
    goto out;
  }
  if ((r = (int)syscall(SYS_landlock_restrict_self, fd, 0)) < 0)
    warn("landlock_restrict_self");
out:
  close(fd);
  return r;
}
