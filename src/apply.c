#include "apply.h"

#include "changes.h"
#include "proc.h"

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/openat2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

int open_beneath(int root, const char *path, int flags) {
  struct open_how how = {
      .flags = (unsigned)(flags | O_CLOEXEC),
      .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
                 RESOLVE_NO_XDEV,
  };
  return openat2(root, *path ? path : ".", &how, sizeof how);
}

// Opens the parent dir of path (O_PATH) and copies the last component
// into name.
static int open_parent(int root, const char *path, char name[NAME_MAX + 1]) {
  char dir[PATH_MAX];
  const char *slash = strrchr(path, '/');

  snprintf(name, NAME_MAX + 1, "%s", slash ? slash + 1 : path);
  snprintf(dir, sizeof dir, "%.*s", slash ? (int)(slash - path) : 0, path);
  return open_beneath(root, dir, O_PATH | O_DIRECTORY);
}

// Removes dirfd/name and everything below it. Never follows a symlink and
// never crosses into another mount (st_dev must stay dev). ENOENT is fine.
static int remove_tree(int dirfd, const char *name, dev_t dev) {
  struct stat st;

  if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0)
    return errno == ENOENT ? 0 : -1;
  if (!S_ISDIR(st.st_mode))
    return unlinkat(dirfd, name, 0);
  if (st.st_dev != dev) {
    errno = EXDEV;
    return -1;
  }
  int fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return -1;
  DIR *d = fdopendir(fd);
  if (!d) {
    close(fd);
    return -1;
  }
  struct dirent *e;
  int r = 0;
  while (r == 0 && (errno = 0, e = readdir(d)))
    if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
      r = remove_tree(fd, e->d_name, dev);
  if (r == 0 && errno != 0)
    r = -1;
  closedir(d);
  return r < 0 ? r : unlinkat(dirfd, name, AT_REMOVEDIR);
}

// Exactly these user.* xattrs on fd: others removed, these set.
static int set_xattrs(int fd, const struct change *c) {
  static char names[XATTR_LIST_MAX];

  ssize_t n = flistxattr(fd, names, sizeof names);
  if (n < 0)
    return -1;
  for (char *p = names; p < names + n; p += strlen(p) + 1) {
    if (strncmp(p, "user.", 5) != 0)
      continue;
    bool keep = false;
    for (size_t i = 0; i < c->nx && !keep; i++)
      keep = strcmp(c->x[i].name, p) == 0;
    if (!keep && fremovexattr(fd, p) < 0)
      return -1;
  }
  for (size_t i = 0; i < c->nx; i++)
    if (fsetxattr(fd, c->x[i].name, c->x[i].value, c->x[i].len, 0) < 0)
      return -1;
  return 0;
}

static int make_file(int pfd, const char *name, const struct change *c) {
  int fd = openat(pfd, name,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0)
    return -1;
  // xattrs before the mode: setting one needs write access to the file.
  if (write_all(fd, c->data, c->len) < 0 || set_xattrs(fd, c) < 0 ||
      fchmod(fd, c->mode) < 0 || fsync(fd) < 0) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  return close(fd);
}

// A dir's mode and xattrs, applied after every entry (see apply.h).
static int finish_dir(int root, const struct change *c) {
  int fd = open_beneath(root, c->path, O_RDONLY | O_DIRECTORY);
  if (fd < 0)
    return -1;
  int r = set_xattrs(fd, c) < 0 || fchmod(fd, c->mode) < 0 ? -1 : 0;
  int e = errno;
  close(fd);
  errno = e;
  return r;
}

// Dirs on the way to a change that lacked u+rwx, opened up for the apply
// and restored at the end: a 0555 dir whose own mode isn't changing must
// still let an approved change below it through.
struct relaxed {
  char path[PATH_MAX];
  mode_t mode;
};
static struct relaxed *relaxed;
static size_t nrelaxed;

static int relax_ancestors(int root, const char *path) {
  struct stat st;
  size_t len = 0;

  for (;;) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%.*s", (int)len, path);
    int fd = open_beneath(root, dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
      return errno == ENOENT ? 0 : -1; // the op itself will report it
    if (fstat(fd, &st) < 0) {
      close(fd);
      return -1;
    }
    if ((st.st_mode & S_IRWXU) != S_IRWXU) {
      struct relaxed *v = reallocarray(relaxed, nrelaxed + 1, sizeof *v);
      if (!v)
        err(1, "reallocarray");
      relaxed = v;
      snprintf(v[nrelaxed].path, PATH_MAX, "%s", dir);
      v[nrelaxed++].mode = st.st_mode & 07777;
      if (fchmod(fd, (st.st_mode & 07777) | S_IRWXU) < 0) {
        close(fd);
        return -1;
      }
    }
    close(fd);
    const char *slash = strchr(path + len + (len ? 1 : 0), '/');
    if (!slash)
      return 0;
    len = (size_t)(slash - path);
  }
}

// Back to the original modes, deepest first. A dir deleted since is fine.
static int restore_ancestors(int root) {
  int r = 0;
  for (size_t i = nrelaxed; i-- > 0;) {
    int fd = open_beneath(root, relaxed[i].path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
      if (errno != ENOENT)
        r = -1;
      continue;
    }
    if (fchmod(fd, relaxed[i].mode) < 0)
      r = -1;
    close(fd);
  }
  free(relaxed);
  relaxed = nullptr;
  nrelaxed = 0;
  return r;
}

static int apply_one(int root, dev_t dev, const struct change *c) {
  char name[NAME_MAX + 1];
  struct stat st;

  if (c->op == 'r')
    return 0; // all in finish_dir
  if (relax_ancestors(root, c->path) < 0)
    return -1;
  int pfd = open_parent(root, c->path, name);
  if (pfd < 0)
    return -1;
  int r;
  switch (c->op) {
  case 'D':
    r = remove_tree(pfd, name, dev);
    break;
  case 'd':
    // An existing dir stays (its entries aren't part of this change); any
    // other type is replaced. u+rwx until finish_dir sets the real mode.
    r = fstatat(pfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(st.st_mode)
            ? fchmodat(pfd, name, (st.st_mode & 07777) | S_IRWXU, 0)
        : remove_tree(pfd, name, dev) < 0 ? -1
                                          : mkdirat(pfd, name, 0700);
    break;
  default: // f, l, p: replace whatever is there
    r = remove_tree(pfd, name, dev);
    if (r == 0 && c->op == 'f')
      r = make_file(pfd, name, c);
    else if (r == 0 && c->op == 'l')
      r = symlinkat(c->data, pfd, name);
    else if (r == 0)
      r = mkfifoat(pfd, name, c->mode) < 0 || fchmodat(pfd, name, c->mode, 0)
              ? -1
              : 0;
  }
  int e = errno;
  close(pfd);
  errno = e;
  return r;
}

int apply_changes(const struct changeset *cs, const char *root) {
  struct stat st;
  const struct change *bad = nullptr;

  int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0 || fstat(fd, &st) < 0) {
    warn("open %s", root);
    if (fd >= 0)
      close(fd);
    return -1;
  }
  for (size_t i = 0; i < cs->n && !bad; i++)
    if (apply_one(fd, st.st_dev, &cs->v[i]) < 0)
      bad = &cs->v[i];
  if (!bad && restore_ancestors(fd) < 0) {
    warn("apply: restoring dir modes");
    close(fd);
    return -1;
  }
  // Deepest first, so a parent loses u+w only after its children are done.
  for (size_t i = cs->n; i-- > 0 && !bad;)
    if ((cs->v[i].op == 'd' || cs->v[i].op == 'r') &&
        finish_dir(fd, &cs->v[i]) < 0)
      bad = &cs->v[i];
  if (bad)
    warn("apply %c %s", bad->op, *bad->path ? bad->path : ".");
  close(fd);
  return bad ? -1 : 0;
}
