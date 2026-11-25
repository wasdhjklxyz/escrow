#include "tree.h"

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static char path[PATH_MAX];

// Every field is NUL-terminated or length-prefixed, so no path or payload
// byte can make two different trees serialize the same.
static void field(struct sha256 *h, const char *s) {
  sha256_write(h, s, strlen(s) + 1);
}

static void field_len(struct sha256 *h, const void *buf, size_t n) {
  char len[32];
  snprintf(len, sizeof len, "%zu", n);
  field(h, len);
  sha256_write(h, buf, n);
}

int tree_skip_dots(const struct dirent *d) {
  return strcmp(d->d_name, ".") != 0 && strcmp(d->d_name, "..") != 0;
}

int tree_by_name(const struct dirent **a, const struct dirent **b) {
  return strcmp((*a)->d_name, (*b)->d_name);
}

static int cmp_str(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}

// user.* xattrs, sorted by name. Others (security.*, trusted.*) can't be
// set by apply anyway; the change set refuses them.
static bool hash_xattrs(struct sha256 *h, int fd) {
  static char names[XATTR_LIST_MAX], val[XATTR_SIZE_MAX];
  static char *list[XATTR_LIST_MAX / 2];
  size_t n = 0;

  ssize_t len = flistxattr(fd, names, sizeof names);
  if (len < 0) {
    warn("listxattr %s", path);
    return false;
  }
  for (char *p = names; p < names + len; p += strlen(p) + 1)
    if (strncmp(p, "user.", 5) == 0)
      list[n++] = p;
  qsort(list, n, sizeof *list, cmp_str);
  for (size_t i = 0; i < n; i++) {
    ssize_t vl = fgetxattr(fd, list[i], val, sizeof val);
    if (vl < 0) {
      warn("getxattr %s %s", path, list[i]);
      return false;
    }
    field(h, "x");
    field(h, list[i]);
    field_len(h, val, (size_t)vl);
  }
  return true;
}

static bool hash_file(struct sha256 *h, int fd) {
  static char buf[1 << 16];
  struct stat st;
  ssize_t n;
  size_t total = 0;

  if (fstat(fd, &st) < 0)
    err(1, "fstat %s", path);
  // Length first, then exactly that many bytes: a file that grows or
  // shrinks while we read it is an error, not a different hash.
  char len[32];
  snprintf(len, sizeof len, "%jd", (intmax_t)st.st_size);
  field(h, len);
  while ((n = read(fd, buf, sizeof buf)) != 0) {
    if (n < 0) {
      if (errno == EINTR)
        continue;
      warn("read %s", path);
      return false;
    }
    total += (size_t)n;
    if (total > (size_t)st.st_size) {
      warnx("%s changed while hashing", path);
      return false;
    }
    sha256_write(h, buf, (size_t)n);
  }
  if (total != (size_t)st.st_size) {
    warnx("%s changed while hashing", path);
    return false;
  }
  return hash_xattrs(h, fd);
}

static bool walk(struct sha256 *h, int dirfd, size_t len);

static bool entry(struct sha256 *h, int dirfd, const char *name, size_t len) {
  char mode[16], target[PATH_MAX];
  struct stat st;
  bool ok = true;

  size_t n = strlen(name);
  if (len + n + 2 > sizeof path)
    errx(1, "path too long: %s%s", path, name);
  memcpy(path + len, name, n + 1);
  if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
    warn("stat %s", path);
    return false;
  }
  snprintf(mode, sizeof mode, "%o", (unsigned)(st.st_mode & 07777));
  if (S_ISREG(st.st_mode)) {
    field(h, "f");
    field(h, mode);
    field(h, path);
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
      warn("open %s", path);
      return false;
    }
    ok = hash_file(h, fd);
    close(fd);
  } else if (S_ISDIR(st.st_mode)) {
    field(h, "d");
    field(h, mode);
    field(h, path);
    int fd =
        openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
      warn("open %s", path);
      return false;
    }
    path[len + n] = '/';
    path[len + n + 1] = '\0';
    ok = hash_xattrs(h, fd) && walk(h, fd, len + n + 1);
    close(fd);
  } else if (S_ISLNK(st.st_mode)) {
    ssize_t tl = readlinkat(dirfd, name, target, sizeof target);
    if (tl < 0 || (size_t)tl >= sizeof target) {
      warn("readlink %s", path);
      return false;
    }
    field(h, "l");
    field(h, mode);
    field(h, path);
    field_len(h, target, (size_t)tl);
  } else {
    char dev[32];
    snprintf(dev, sizeof dev, "%ju", (uintmax_t)st.st_rdev);
    field(h, S_ISFIFO(st.st_mode)   ? "p"
             : S_ISSOCK(st.st_mode) ? "s"
             : S_ISCHR(st.st_mode)  ? "c"
                                    : "b");
    field(h, mode);
    field(h, path);
    field(h, dev);
  }
  path[len] = '\0';
  return ok;
}

static bool walk(struct sha256 *h, int dirfd, size_t len) {
  struct dirent **ents;
  bool ok = true;

  int n = scandirat(dirfd, ".", &ents, tree_skip_dots, tree_by_name);
  if (n < 0) {
    warn("scandir %s", len ? path : ".");
    return false;
  }
  for (int i = 0; i < n; i++) {
    if (ok)
      ok = entry(h, dirfd, ents[i]->d_name, len);
    free(ents[i]);
  }
  free(ents);
  field(h, "end");
  return ok;
}

bool tree_hash(const char *dir, char hex[SHA256_HEX + 1]) {
  struct sha256 h;
  struct stat st;

  int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0)
    err(1, "open %s", dir);
  if (fstat(fd, &st) < 0)
    err(1, "fstat %s", dir);
  char mode[16];
  snprintf(mode, sizeof mode, "%o", (unsigned)(st.st_mode & 07777));
  path[0] = '\0';
  sha256_open(&h);
  field(&h, "escrow-tree 1");
  field(&h, mode);
  bool ok = hash_xattrs(&h, fd) && walk(&h, fd, 0);
  close(fd);
  sha256_close(&h, hex);
  return ok;
}
