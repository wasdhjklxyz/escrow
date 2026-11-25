#include "apply.h"

#include "changes.h"

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

enum { XATTR_BUF = 1 << 16 };

static int resolve(int root, const char *path, int flags) {
  struct open_how how = {
      .flags = (unsigned)(flags | O_CLOEXEC),
      .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
                 RESOLVE_NO_XDEV,
  };
  return (int)syscall(SYS_openat2, root, path, &how, sizeof how);
}

// Opens the parent dir of path (O_PATH) and points *name at the last
// component.
static int parent(int root, char *path, const char **name) {
  char *slash = strrchr(path, '/');
  if (!slash) {
    *name = path;
    return resolve(root, ".", O_PATH | O_DIRECTORY);
  }
  *slash = '\0';
  int fd = resolve(root, path, O_PATH | O_DIRECTORY);
  *slash = '/';
  *name = slash + 1;
  return fd;
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
  while (r == 0 && (errno = 0, e = readdir(d))) {
    if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
      r = remove_tree(fd, e->d_name, dev);
  }
  if (r == 0 && errno)
    r = -1;
  closedir(d);
  return r ? r : unlinkat(dirfd, name, AT_REMOVEDIR);
}

// Clears whatever is at dirfd/name unless it is a dir and keep_dir.
static int clear(int dirfd, const char *name, bool keep_dir, dev_t dev) {
  struct stat st;

  if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0)
    return errno == ENOENT ? 0 : -1;
  if (keep_dir && S_ISDIR(st.st_mode))
    return 0;
  return remove_tree(dirfd, name, dev);
}

// Exactly these user.* xattrs on fd: others removed, these set.
static int set_xattrs(int fd, const struct change *c) {
  static char names[XATTR_BUF];

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

static int write_all(int fd, const char *p, size_t n) {
  while (n > 0) {
    ssize_t w = write(fd, p, n);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    p += w;
    n -= (size_t)w;
  }
  return 0;
}

static void temp_name(char out[32]) {
  unsigned char r[6];
  if (getrandom(r, sizeof r, 0) != sizeof r)
    err(1, "getrandom");
  snprintf(out, 32, ".escrow-%02x%02x%02x%02x%02x%02x", r[0], r[1], r[2], r[3],
           r[4], r[5]);
}

// Creates the f/l/p entry under a temp name in dirfd and returns 0 with
// the name in tmp.
static int make_temp(int dirfd, const struct change *c, char tmp[32]) {
  temp_name(tmp);
  if (c->op == 'l')
    return symlinkat(c->data, dirfd, tmp);
  if (c->op == 'p')
    return mkfifoat(dirfd, tmp, c->mode) < 0 ||
                   fchmodat(dirfd, tmp, c->mode, 0) < 0
               ? -1
               : 0;
  int fd = openat(dirfd, tmp,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0)
    return -1;
  if (write_all(fd, c->data, c->len) < 0 || fchmod(fd, c->mode) < 0 ||
      set_xattrs(fd, c) < 0 || fsync(fd) < 0) {
    int e = errno;
    close(fd);
    unlinkat(dirfd, tmp, 0);
    errno = e;
    return -1;
  }
  return close(fd);
}

static int apply_one(int root, dev_t dev, struct change *c) {
  const char *name;
  char tmp[32];

  if (c->op == 'r') {
    int fd = resolve(root, ".", O_RDONLY | O_DIRECTORY);
    if (fd < 0)
      return -1;
    int r = fchmod(fd, c->mode) < 0 || set_xattrs(fd, c) < 0 ? -1 : 0;
    close(fd);
    return r;
  }
  int pfd = parent(root, c->path, &name);
  if (pfd < 0)
    return -1;
  int r = -1;
  switch (c->op) {
  case 'D':
    r = remove_tree(pfd, name, dev);
    break;
  case 'd': {
    if (clear(pfd, name, true, dev) < 0 ||
        (mkdirat(pfd, name, c->mode) < 0 && errno != EEXIST))
      break;
    int fd = resolve(pfd, name, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
      break;
    r = fchmod(fd, c->mode) < 0 || set_xattrs(fd, c) < 0 ? -1 : 0;
    close(fd);
    break;
  }
  default: // f, l, p
    if (make_temp(pfd, c, tmp) < 0)
      break;
    if (clear(pfd, name, false, dev) < 0 || renameat(pfd, tmp, pfd, name) < 0) {
      int e = errno;
      unlinkat(pfd, tmp, 0);
      errno = e;
      break;
    }
    r = 0;
  }
  int e = errno;
  close(pfd);
  errno = e;
  return r;
}

int apply_changes(const struct changeset *cs, const char *root) {
  struct stat st;

  int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0 || fstat(fd, &st) < 0) {
    warn("open %s", root);
    if (fd >= 0)
      close(fd);
    return -1;
  }
  for (size_t i = 0; i < cs->n; i++) {
    if (apply_one(fd, st.st_dev, &cs->v[i]) < 0) {
      warn("apply %c %s", cs->v[i].op, *cs->v[i].path ? cs->v[i].path : ".");
      close(fd);
      return -1;
    }
  }
  close(fd);
  return 0;
}
