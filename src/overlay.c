#include "overlay.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static void join(char out[PATH_MAX], const char *dir, const char *name) {
  int n = snprintf(out, PATH_MAX, "%s/%s", dir, name);
  if (n < 0 || n >= PATH_MAX)
    errx(1, "path too long: %s/%s", dir, name);
}

// True if path is dir or lies below it. Both must be realpath() output, so
// a prefix match on a '/' boundary is exact.
static bool within(const char *path, const char *dir) {
  size_t n = strlen(dir);
  if (strcmp(dir, "/") == 0)
    return true;
  return strncmp(path, dir, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

// realpath() for a path whose last component may not exist yet: resolve
// the parent and append the name, so the overlap check can run before
// mkdir.
static void resolve(const char *path, char out[PATH_MAX]) {
  char a[PATH_MAX], b[PATH_MAX], parent[PATH_MAX];

  if (realpath(path, out))
    return;
  if (errno != ENOENT)
    err(1, "%s", path);
  if (strlen(path) >= PATH_MAX)
    errx(1, "path too long: %s", path);
  strcpy(a, path);
  strcpy(b, path);
  const char *name = basename(b);
  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    errx(1, "%s: not a usable state dir", path);
  if (!realpath(dirname(a), parent))
    err(1, "%s", a);
  join(out, parent, name);
}

static void mkdir_existing_ok(const char *path) {
  if (mkdir(path, 0700) < 0 && errno != EEXIST)
    err(1, "mkdir %s", path);
}

static void mkdir_new(char out[PATH_MAX], const char *dir, const char *name) {
  join(out, dir, name);
  if (mkdir(out, 0700) < 0)
    err(1, "mkdir %s", out);
}

void overlay_prepare(struct run *run, const char *state, const char *ws) {
  char path[PATH_MAX], runs[PATH_MAX];

  resolve(state, path);
  if (within(path, ws))
    errx(1, "state dir %s is inside workspace %s", path, ws);
  mkdir_existing_ok(path);

  // runs/ may already exist as a symlink: resolve it again before mkdtemp.
  join(runs, path, "runs");
  mkdir_existing_ok(runs);
  if (!realpath(runs, path))
    err(1, "%s", runs);
  if (within(path, ws))
    errx(1, "state dir %s is inside workspace %s", path, ws);

  // path is canonical and mkdtemp only swaps in a plain name, so run->dir
  // is canonical too. It is brand new and empty, so ws can't be inside it.
  join(run->dir, path, "XXXXXX");
  if (!mkdtemp(run->dir))
    err(1, "mkdtemp %s", run->dir);
  mkdir_new(run->upper, run->dir, "upper");
  mkdir_new(run->work, run->dir, "work");
  mkdir_new(run->merged, run->dir, "merged");
}

static int set(int fsfd, const char *key, const char *val) {
  int r = val ? fsconfig(fsfd, FSCONFIG_SET_STRING, key, val, 0)
              : fsconfig(fsfd, FSCONFIG_SET_FLAG, key, nullptr, 0);
  if (r < 0)
    warn("fsconfig %s", key);
  return r;
}

// The kernel queues human-readable reasons ("e overlay: ...") on the fs
// context fd. Without them most failures are a bare EINVAL.
static void drain_log(int fsfd) {
  char buf[4096];
  ssize_t n;

  while ((n = read(fsfd, buf, sizeof buf)) > 0)
    warnx("%.*s", (int)n, buf);
}

int overlay_mount(const struct run *run, const char *ws) {
  int fsfd = fsopen("overlay", FSOPEN_CLOEXEC);
  if (fsfd < 0) {
    warn("fsopen overlay");
    return -1;
  }

  // One path per fsconfig call: no ',' ':' '\' escaping, so a workspace
  // path can't smuggle in extra mount options. userxattr makes overlay use
  // user.overlay.* xattrs, the only kind it may set from a user ns.
  if (set(fsfd, "lowerdir+", ws) < 0 || set(fsfd, "upperdir", run->upper) < 0 ||
      set(fsfd, "workdir", run->work) < 0 ||
      set(fsfd, "userxattr", nullptr) < 0)
    goto fail;
  if (fsconfig(fsfd, FSCONFIG_CMD_CREATE, nullptr, nullptr, 0) < 0) {
    warn("fsconfig create");
    goto fail;
  }

  int mfd =
      fsmount(fsfd, FSMOUNT_CLOEXEC, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV);
  if (mfd < 0) {
    warn("fsmount");
    goto fail;
  }
  if (move_mount(mfd, "", AT_FDCWD, run->merged, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
    warn("move_mount %s", run->merged);
    close(mfd);
    goto fail;
  }
  if (close(mfd) < 0 || close(fsfd) < 0) {
    warn("close");
    return -1;
  }
  return 0;

fail:
  drain_log(fsfd);
  close(fsfd);
  return -1;
}
