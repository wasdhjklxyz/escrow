#include "diff.h"

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <unistd.h>

// Lower-side dir fd sentinels: no lower dir at all (everything is new), or
// a lower dir exists but we can't read it (nothing can be compared).
enum { LOWER_NONE = -1, LOWER_UNKNOWN = -2 };

// Result of looking an entry up on the lower side.
enum lookup { ABSENT, PRESENT, UNKNOWN };

// Result of comparing an upper entry with its lower counterpart.
enum cmp { SAME, CHANGED, UNREADABLE };

// Relative path of the entry being visited. Every name is appended with
// push(), and a directory's prefix ends in '/'.
static char path[PATH_MAX];
static bool complete = true;

// The agent may chmod upper entries so we (the same uid, without its
// in-ns capabilities) can't read them. We add u+r(x) for the walk and put
// the mode back afterwards. The list lives in the walk's stack frames, and
// atexit restores whatever is still relaxed if err() exits mid-walk.
struct relaxed {
  int dirfd;
  const char *name;
  mode_t mode;
  struct relaxed *next;
};
static struct relaxed *relaxed;

static void restore_all(void) {
  for (; relaxed; relaxed = relaxed->next)
    if (fchmodat(relaxed->dirfd, relaxed->name, relaxed->mode, 0) < 0)
      warn("restore mode of upper entry %s", relaxed->name);
}

static bool relax(struct relaxed *r, int dirfd, const char *name, mode_t mode,
                  mode_t need) {
  if ((mode & need) == need)
    return false;
  if (fchmodat(dirfd, name, (mode | need) & 07777, 0) < 0)
    err(1, "chmod upper %s", path);
  *r = (struct relaxed){dirfd, name, mode & 07777, relaxed};
  relaxed = r;
  return true;
}

static void unrelax(void) {
  struct relaxed *r = relaxed;

  relaxed = r->next;
  if (fchmodat(r->dirfd, r->name, r->mode, 0) < 0)
    err(1, "restore mode of upper %s", path);
}

static size_t push(size_t len, const char *name) {
  size_t n = strlen(name);
  if (len + n + 2 > sizeof path)
    errx(1, "path too long: %s%s", path, name);
  memcpy(path + len, name, n + 1);
  return len + n;
}

// The root's prefix stays empty, so top-level entries print bare.
static size_t descend(size_t len) {
  if (len == 0)
    return 0;
  path[len] = '/';
  path[len + 1] = '\0';
  return len + 1;
}

static void emit(char tag, const char *suffix) {
  printf("%c %s%s\n", tag, path, suffix);
  if (tag == '?')
    complete = false;
}

static const char *type_tag(mode_t mode) {
  switch (mode & S_IFMT) {
  case S_IFIFO:
    return " (fifo)";
  case S_IFSOCK:
    return " (socket)";
  case S_IFCHR:
    return " (char)";
  case S_IFBLK:
    return " (block)";
  default:
    return "";
  }
}

static bool is_whiteout(const struct stat *st) {
  return S_ISCHR(st->st_mode) && st->st_rdev == makedev(0, 0);
}

// Never follows a symlink: a workspace symlink must not walk us out of
// the workspace.
static int open_dir(int dirfd, const char *name) {
  return openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

static int open_lower_dir(int lfd, const char *name) {
  int fd = open_dir(lfd, name);
  if (fd < 0) {
    if (errno != EACCES)
      err(1, "open workspace %s", path);
    return LOWER_UNKNOWN;
  }
  return fd;
}

static enum lookup lookup(int lfd, const char *name, struct stat *st) {
  if (lfd == LOWER_NONE)
    return ABSENT;
  if (lfd == LOWER_UNKNOWN)
    return UNKNOWN;
  if (fstatat(lfd, name, st, AT_SYMLINK_NOFOLLOW) == 0)
    return PRESENT;
  if (errno == ENOENT)
    return ABSENT;
  if (errno == EACCES)
    return UNKNOWN;
  err(1, "stat workspace %s", path);
}

// Overlay stops lower lookups below a dir marked opaque (it was deleted
// and recreated), so lower entries missing from upper are deleted.
static bool is_opaque(int fd) {
  char v[2];
  ssize_t n = fgetxattr(fd, "user.overlay.opaque", v, sizeof v);
  if (n < 0) {
    if (errno == ENODATA || errno == ERANGE)
      return false;
    err(1, "getxattr upper %s", path);
  }
  return n == 1 && v[0] == 'y';
}

static int skip_dots(const struct dirent *d) {
  return strcmp(d->d_name, ".") != 0 && strcmp(d->d_name, "..") != 0;
}

// strcmp, not alphasort: output order must not depend on the locale.
static int by_name(const struct dirent **a, const struct dirent **b) {
  return strcmp((*a)->d_name, (*b)->d_name);
}

static int list(int fd, struct dirent ***ents) {
  int n = scandirat(fd, ".", ents, skip_dots, by_name);
  if (n < 0)
    err(1, "scandir %s", path);
  return n;
}

static void free_list(struct dirent **ents, int n) {
  for (int i = 0; i < n; i++)
    free(ents[i]);
  free(ents);
}

static void gone(int lfd, const char *name, const struct stat *st, size_t len);

// Every entry below lower dir `name` is gone from the merged view.
static void gone_children(int lfd, const char *name, size_t len) {
  struct dirent **ents;
  struct stat st;

  int fd = open_lower_dir(lfd, name);
  if (fd == LOWER_UNKNOWN) {
    emit('?', "/");
    return;
  }
  size_t sub = descend(len);
  int n = list(fd, &ents);
  for (int i = 0; i < n; i++) {
    size_t l = push(sub, ents[i]->d_name);
    if (fstatat(fd, ents[i]->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
      if (errno != EACCES)
        err(1, "stat workspace %s", path);
      emit('?', "");
      continue;
    }
    gone(fd, ents[i]->d_name, &st, l);
  }
  path[len] = '\0';
  free_list(ents, n);
  if (close(fd) < 0)
    err(1, "close");
}

// Lower entry `name` (path[0..len)) is gone from the merged view.
static void gone(int lfd, const char *name, const struct stat *st, size_t len) {
  if (!S_ISDIR(st->st_mode)) {
    emit('D', type_tag(st->st_mode));
    return;
  }
  emit('D', "/");
  gone_children(lfd, name, len);
}

static ssize_t read_full(int fd, char *buf, size_t n) {
  size_t got = 0;

  while (got < n) {
    ssize_t r = read(fd, buf + got, n - got);
    if (r < 0) {
      if (errno == EINTR)
        continue;
      err(1, "read %s", path);
    }
    if (r == 0)
      break;
    got += r;
  }
  return got;
}

static bool same_bytes(int a, int b) {
  static char ba[1 << 16], bb[1 << 16];

  for (;;) {
    ssize_t na = read_full(a, ba, sizeof ba);
    ssize_t nb = read_full(b, bb, sizeof bb);
    if (na != nb || memcmp(ba, bb, na) != 0)
      return false;
    if (na == 0)
      return true;
  }
}

// Same-type, non-dir entries. Equal content and mode is not a change:
// overlay copies a file up on any open for writing, even with no write.
static enum cmp differs(int ufd, int lfd, const char *name,
                        const struct stat *u, const struct stat *l) {
  if (S_ISLNK(u->st_mode)) {
    char a[PATH_MAX], b[PATH_MAX];
    ssize_t na = readlinkat(ufd, name, a, sizeof a);
    if (na < 0)
      err(1, "readlink upper %s", path);
    ssize_t nb = readlinkat(lfd, name, b, sizeof b);
    if (nb < 0)
      err(1, "readlink workspace %s", path);
    return na != nb || memcmp(a, b, na) != 0 ? CHANGED : SAME;
  }
  if ((u->st_mode ^ l->st_mode) & 07777)
    return CHANGED;
  if (S_ISCHR(u->st_mode) || S_ISBLK(u->st_mode))
    return u->st_rdev != l->st_rdev ? CHANGED : SAME;
  if (!S_ISREG(u->st_mode))
    return SAME;
  if (u->st_size != l->st_size)
    return CHANGED;

  int lf = openat(lfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (lf < 0) {
    if (errno != EACCES)
      err(1, "open workspace %s", path);
    return UNREADABLE;
  }
  struct relaxed r;
  bool relaxed_here = relax(&r, ufd, name, u->st_mode, S_IRUSR);
  int uf = openat(ufd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (uf < 0)
    err(1, "open upper %s", path);
  bool same = same_bytes(uf, lf);
  if (close(uf) < 0 || close(lf) < 0)
    err(1, "close");
  if (relaxed_here)
    unrelax();
  return same ? SAME : CHANGED;
}

static void walk(int ufd, int lfd, bool opaque, size_t len);

// Upper dir `name` (path[0..len)), walked against lower dir fd lfd or a
// LOWER_* sentinel. Takes ownership of lfd.
static void dir(int ufd, const char *name, mode_t mode, int lfd, bool opaque,
                size_t len) {
  struct relaxed r;
  bool relaxed_here = relax(&r, ufd, name, mode, S_IRUSR | S_IXUSR);

  int fd = open_dir(ufd, name);
  if (fd < 0)
    err(1, "open upper %s", path);
  walk(fd, lfd, opaque || is_opaque(fd), descend(len));
  path[len] = '\0';
  if (close(fd) < 0 || (lfd >= 0 && close(lfd) < 0))
    err(1, "close");
  if (relaxed_here)
    unrelax();
}

// One upper entry `name` (path[0..len)) of a dir whose lower side is lfd.
static void entry(int ufd, int lfd, bool opaque, const char *name, size_t len) {
  struct stat u, l;

  if (fstatat(ufd, name, &u, AT_SYMLINK_NOFOLLOW) < 0)
    err(1, "stat upper %s", path);
  enum lookup lower = lookup(lfd, name, &l);

  if (is_whiteout(&u)) {
    if (lower == PRESENT)
      gone(lfd, name, &l, len);
    else if (lower == UNKNOWN)
      emit('?', "");
    return;
  }

  if (S_ISDIR(u.st_mode)) {
    int sub = LOWER_NONE;
    if (lower == ABSENT) {
      emit('A', "/");
    } else if (lower == UNKNOWN) {
      emit('?', "/");
      sub = LOWER_UNKNOWN;
    } else if (!S_ISDIR(l.st_mode)) {
      emit('M', "/"); // type change: lower non-dir replaced by a dir
    } else {
      if ((u.st_mode ^ l.st_mode) & 07777)
        emit('M', "/");
      sub = open_lower_dir(lfd, name);
      if (sub == LOWER_UNKNOWN)
        emit('?', "/");
    }
    dir(ufd, name, u.st_mode, sub, opaque, len);
    return;
  }

  const char *tag = type_tag(u.st_mode);
  if (lower == ABSENT) {
    emit('A', tag);
  } else if (lower == UNKNOWN) {
    emit('?', tag);
  } else if ((u.st_mode ^ l.st_mode) & S_IFMT) {
    emit('M', tag); // type change
    if (S_ISDIR(l.st_mode))
      gone_children(lfd, name, len);
  } else {
    switch (differs(ufd, lfd, name, &u, &l)) {
    case CHANGED:
      emit('M', tag);
      break;
    case UNREADABLE:
      emit('?', tag);
      break;
    case SAME:
      break;
    }
  }
}

// Merge-walks one directory level. Upper entries are always visited. In an
// opaque dir, lower entries with no upper counterpart are also deletions.
static void walk(int ufd, int lfd, bool opaque, size_t len) {
  struct dirent **u, **l = nullptr;
  int nu = list(ufd, &u), nl = 0;

  if (opaque && lfd >= 0)
    nl = list(lfd, &l);
  for (int i = 0, j = 0; i < nu || j < nl;) {
    int c = i == nu ? 1 : j == nl ? -1 : strcmp(u[i]->d_name, l[j]->d_name);
    if (c > 0) {
      const char *name = l[j++]->d_name;
      size_t n = push(len, name);
      struct stat st;
      if (fstatat(lfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
        if (errno != EACCES)
          err(1, "stat workspace %s", path);
        emit('?', "");
        continue;
      }
      gone(lfd, name, &st, n);
      continue;
    }
    if (c == 0)
      j++;
    const char *name = u[i++]->d_name;
    entry(ufd, lfd, opaque, name, push(len, name));
  }
  path[len] = '\0';
  free_list(u, nu);
  if (l)
    free_list(l, nl);
}

bool diff_print(const char *upper, const char *ws) {
  char parent[PATH_MAX];
  struct stat st;

  if (atexit(restore_all) != 0)
    errx(1, "atexit");

  // Open upper via its parent so a chmod'ed upper root can be relaxed too.
  // The root's own mode is not compared: we created upper, so it never
  // matches the workspace root.
  const char *slash = strrchr(upper, '/');
  if (!slash || slash == upper || (size_t)(slash - upper) >= sizeof parent)
    errx(1, "bad upper dir path: %s", upper);
  memcpy(parent, upper, slash - upper);
  parent[slash - upper] = '\0';
  int pfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (pfd < 0)
    err(1, "open %s", parent);
  if (fstatat(pfd, slash + 1, &st, AT_SYMLINK_NOFOLLOW) < 0)
    err(1, "stat %s", upper);

  int lfd = open(ws, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (lfd < 0) {
    if (errno != EACCES)
      err(1, "open %s", ws);
    lfd = LOWER_UNKNOWN;
    emit('?', "./");
  }
  dir(pfd, slash + 1, st.st_mode, lfd, false, 0);
  if (close(pfd) < 0)
    err(1, "close");
  if (fflush(stdout) == EOF)
    err(1, "stdout");
  return complete;
}
