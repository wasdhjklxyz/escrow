#include "diff.h"

#include "overlay.h"

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
enum { LOWER_NONE = -1, LOWER_UNREADABLE = -2 };

// Result of looking an entry up on the lower side.
enum lookup { LOOKUP_ABSENT, LOOKUP_PRESENT, LOOKUP_UNREADABLE };

// Result of comparing an upper entry with its lower counterpart.
enum cmp { CMP_SAME, CMP_CHANGED, CMP_UNREADABLE };

// Worst case for quote(): every byte becomes \ooo, plus quotes and NUL.
enum { QUOTE_MAX = 4 * PATH_MAX + 3 };

// Kernel cap on one xattr value and on a name list (XATTR_SIZE_MAX,
// XATTR_LIST_MAX).
enum { XATTR_BUF = 1 << 16 };

// Relative path of the entry being visited. Every name is appended with
// push(), and a directory's prefix ends in '/'.
static char path[PATH_MAX];
static bool complete = true;

// The agent may chmod upper entries so we (the same uid, without its
// in-ns capabilities) can't read them. The walk adds u+r(x) and restores
// the mode afterwards, so it does modify the change set while it runs.
// Guarantee: each entry is pushed *before* its chmod, popped after its
// restore, and atexit restores whatever is still pushed if err() exits
// mid-walk. TERM/HUP don't kill us while the walk runs (see jail.c).
// Only SIGKILL can leave a mode relaxed.
struct relax_entry {
  int dirfd;
  const char *name;
  mode_t mode;
  struct relax_entry *next;
};
static struct relax_entry *relaxed_head;

// Copies s to out, C-quoted if it holds any byte that could forge or hide
// a line on a terminal or for a line parser: control bytes, space, '"',
// '\', and non-ASCII (which includes bidi overrides). An unquoted path
// therefore never contains a space, so the " (fifo)" and " -> target"
// suffixes are unambiguous.
static void quote(char out[QUOTE_MAX], const char *s) {
  const unsigned char *p;

  for (p = (const unsigned char *)s; *p; p++)
    if (*p <= ' ' || *p >= 0x7f || *p == '"' || *p == '\\')
      break;
  if (!*p) {
    strcpy(out, s);
    return;
  }
  *out++ = '"';
  for (p = (const unsigned char *)s; *p; p++) {
    if (*p == '"' || *p == '\\') {
      *out++ = '\\';
      *out++ = *p;
    } else if (*p < ' ' || *p >= 0x7f) {
      out += sprintf(out, "\\%03o", *p);
    } else {
      *out++ = *p;
    }
  }
  *out++ = '"';
  *out = '\0';
}

// The current path, quoted, for error messages.
static const char *where(void) {
  static char buf[QUOTE_MAX];

  quote(buf, path[0] ? path : ".");
  return buf;
}

static void restore_all(void) {
  for (; relaxed_head; relaxed_head = relaxed_head->next)
    if (fchmodat(relaxed_head->dirfd, relaxed_head->name, relaxed_head->mode,
                 AT_SYMLINK_NOFOLLOW) < 0)
      warn("restore mode of an upper entry");
}

// AT_SYMLINK_NOFOLLOW: never chmod through a symlink. Only dirs and
// regular files are relaxed, so this is defense in depth (glibc uses
// fchmodat2, kernel >= 6.6).
static bool relax(struct relax_entry *r, int dirfd, const char *name,
                  mode_t mode, mode_t need) {
  if ((mode & need) == need)
    return false;
  *r = (struct relax_entry){dirfd, name, mode & ALLPERMS, relaxed_head};
  relaxed_head = r;
  if (fchmodat(dirfd, name, (mode | need) & ALLPERMS, AT_SYMLINK_NOFOLLOW) < 0)
    err(1, "chmod upper %s", where());
  return true;
}

static void restore(void) {
  struct relax_entry *r = relaxed_head;

  relaxed_head = r->next;
  if (fchmodat(r->dirfd, r->name, r->mode, AT_SYMLINK_NOFOLLOW) < 0)
    err(1, "restore mode of upper %s", where());
}

static size_t push(size_t len, const char *name) {
  size_t n = strlen(name);
  if (len + n + 2 > sizeof path)
    errx(1, "path too long: %s", where());
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

static const char *type_suffix(mode_t mode) {
  switch (mode & S_IFMT) {
  case S_IFLNK:
    return " (symlink)";
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

// Overlay's own bookkeeping (opaque, origin, impure, ...), not the agent's.
static bool is_overlay_xattr(const char *name) {
  return strncmp(name, "user.overlay.", 13) == 0 ||
         strncmp(name, "trusted.overlay.", 16) == 0;
}

static ssize_t list_xattrs(int fd, char buf[XATTR_BUF]) {
  ssize_t n = flistxattr(fd, buf, XATTR_BUF);
  if (n < 0) {
    if (errno == ENOTSUP)
      return 0;
    err(1, "listxattr %s", where());
  }
  return n;
}

// True if b lacks one of a's non-overlay xattrs (names in alist) or holds
// it with a different value.
static bool xattrs_missing(int a, int b, const char *alist, ssize_t n) {
  static char va[XATTR_BUF], vb[XATTR_BUF];

  for (const char *p = alist; p < alist + n; p += strlen(p) + 1) {
    if (is_overlay_xattr(p))
      continue;
    ssize_t na = fgetxattr(a, p, va, sizeof va);
    if (na < 0)
      err(1, "getxattr %s", where());
    ssize_t nb = fgetxattr(b, p, vb, sizeof vb);
    if (nb < 0) {
      if (errno == ENODATA)
        return true;
      err(1, "getxattr %s", where());
    }
    if (na != nb || memcmp(va, vb, na) != 0)
      return true;
  }
  return false;
}

// Agent-set xattrs (security.capability above all) change what a file can
// do without touching its bytes or mode, so they count as a modification.
static bool xattrs_differ(int ufd, int lfd) {
  static char ul[XATTR_BUF], ll[XATTR_BUF];
  ssize_t un = list_xattrs(ufd, ul), ln = list_xattrs(lfd, ll);

  return xattrs_missing(ufd, lfd, ul, un) || xattrs_missing(lfd, ufd, ll, ln);
}

// Appends " xattrs: <name>..." for the non-overlay xattrs on fd, so an
// added or modified entry shows what metadata it carries.
static void print_xattrs(int fd) {
  static char names[XATTR_BUF], q[QUOTE_MAX];
  ssize_t n = list_xattrs(fd, names);
  bool first = true;

  for (const char *p = names; p < names + n; p += strlen(p) + 1) {
    if (is_overlay_xattr(p))
      continue;
    quote(q, p);
    printf("%s%s", first ? " xattrs: " : " ", q);
    first = false;
  }
}

// The one place a diff line is printed. mode gives the trailing '/' and the
// type suffix (0 if unknown). For a symlink with a dirfd, the target is
// shown instead of " (symlink)", so the reviewer sees where it points.
// xfd, if >= 0, is the open upper entry whose xattrs are listed.
static void emit(char tag, mode_t mode, int dirfd, const char *name, int xfd) {
  static char q[QUOTE_MAX];
  size_t len = strlen(path);

  if (len == 0) {
    quote(q, "./");
  } else if (S_ISDIR(mode)) {
    path[len] = '/'; // push() left room
    path[len + 1] = '\0';
    quote(q, path);
    path[len] = '\0';
  } else {
    quote(q, path);
  }

  if (S_ISLNK(mode) && dirfd >= 0) {
    char target[PATH_MAX];
    ssize_t n = readlinkat(dirfd, name, target, sizeof target);
    if (n < 0)
      err(1, "readlink upper %s", where());
    if ((size_t)n == sizeof target)
      errx(1, "symlink target too long: %s", where());
    target[n] = '\0';
    printf("%c %s -> ", tag, q);
    quote(q, target);
    printf("%s", q);
  } else {
    printf("%c %s%s", tag, q, type_suffix(mode));
  }
  if (xfd >= 0)
    print_xattrs(xfd);
  putchar('\n');
  if (tag == '?')
    complete = false;
}

static bool is_whiteout(const struct stat *st) {
  return S_ISCHR(st->st_mode) && st->st_rdev == makedev(0, 0);
}

static bool mode_differs(const struct stat *a, const struct stat *b) {
  return (a->st_mode ^ b->st_mode) & ALLPERMS;
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
      err(1, "open workspace %s", where());
    return LOWER_UNREADABLE;
  }
  return fd;
}

static enum lookup lookup(int lfd, const char *name, struct stat *st) {
  if (lfd == LOWER_NONE)
    return LOOKUP_ABSENT;
  if (lfd == LOWER_UNREADABLE)
    return LOOKUP_UNREADABLE;
  if (fstatat(lfd, name, st, AT_SYMLINK_NOFOLLOW) == 0)
    return LOOKUP_PRESENT;
  if (errno == ENOENT)
    return LOOKUP_ABSENT;
  if (errno == EACCES)
    return LOOKUP_UNREADABLE;
  err(1, "stat workspace %s", where());
}

// Overlay stops lower lookups below a dir marked opaque (it was deleted
// and recreated), so lower entries missing from upper are deleted.
static bool is_opaque(int fd) {
  char v[2];
  ssize_t n = fgetxattr(fd, "user.overlay.opaque", v, sizeof v);
  if (n < 0) {
    if (errno == ENODATA || errno == ERANGE)
      return false;
    err(1, "getxattr upper %s", where());
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

static int list(int fd, const char *side, struct dirent ***ents) {
  int n = scandirat(fd, ".", ents, skip_dots, by_name);
  if (n < 0)
    err(1, "scandir %s %s", side, where());
  return n;
}

static void free_list(struct dirent **ents, int n) {
  for (int i = 0; i < n; i++)
    free(ents[i]);
  free(ents);
}

static void gone_name(int lfd, const char *name, size_t len);

// Every entry below lower dir `name` (path[0..len)) is gone from the
// merged view.
static void gone_children(int lfd, const char *name, size_t len) {
  struct dirent **ents;

  int fd = open_lower_dir(lfd, name);
  if (fd == LOWER_UNREADABLE) {
    emit('?', S_IFDIR, -1, name, -1);
    return;
  }
  size_t sub = descend(len);
  int n = list(fd, "workspace", &ents);
  for (int i = 0; i < n; i++)
    gone_name(fd, ents[i]->d_name, push(sub, ents[i]->d_name));
  path[len] = '\0';
  free_list(ents, n);
  if (close(fd) < 0)
    err(1, "close workspace %s", where());
}

// Lower entry `name` (path[0..len)) is gone from the merged view.
static void gone_name(int lfd, const char *name, size_t len) {
  struct stat st;

  if (fstatat(lfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
    if (errno != EACCES)
      err(1, "stat workspace %s", where());
    emit('?', 0, -1, name, -1);
    return;
  }
  emit('D', st.st_mode, -1, name, -1);
  if (S_ISDIR(st.st_mode))
    gone_children(lfd, name, len);
}

static size_t read_full(int fd, char *buf, size_t n) {
  size_t got = 0;

  while (got < n) {
    ssize_t r = read(fd, buf + got, n - got);
    if (r < 0) {
      if (errno == EINTR)
        continue;
      err(1, "read %s", where());
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
    size_t na = read_full(a, ba, sizeof ba);
    size_t nb = read_full(b, bb, sizeof bb);
    if (na != nb || memcmp(ba, bb, na) != 0)
      return false;
    if (na == 0)
      return true;
  }
}

// Same-type, non-dir entries. Equal content and mode is not a change:
// overlay copies a file up on any open for writing, even with no write.
static enum cmp compare(int ufd, int lfd, const char *name,
                        const struct stat *u, const struct stat *l) {
  if (S_ISLNK(u->st_mode)) {
    char a[PATH_MAX], b[PATH_MAX];
    ssize_t na = readlinkat(ufd, name, a, sizeof a);
    if (na < 0)
      err(1, "readlink upper %s", where());
    ssize_t nb = readlinkat(lfd, name, b, sizeof b);
    if (nb < 0)
      err(1, "readlink workspace %s", where());
    return na != nb || memcmp(a, b, na) != 0 ? CMP_CHANGED : CMP_SAME;
  }
  if (mode_differs(u, l))
    return CMP_CHANGED;
  if (S_ISCHR(u->st_mode) || S_ISBLK(u->st_mode))
    return u->st_rdev != l->st_rdev ? CMP_CHANGED : CMP_SAME;
  if (!S_ISREG(u->st_mode))
    return CMP_SAME;
  if (u->st_size != l->st_size)
    return CMP_CHANGED;

  int lf = openat(lfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (lf < 0) {
    if (errno != EACCES)
      err(1, "open workspace %s", where());
    return CMP_UNREADABLE;
  }
  struct relax_entry r;
  bool relaxed = relax(&r, ufd, name, u->st_mode, S_IRUSR);
  int uf = openat(ufd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (uf < 0)
    err(1, "open upper %s", where());
  bool same = same_bytes(uf, lf) && !xattrs_differ(uf, lf);
  if (close(uf) < 0 || close(lf) < 0)
    err(1, "close %s", where());
  if (relaxed)
    restore();
  return same ? CMP_SAME : CMP_CHANGED;
}

static void walk(int ufd, int lfd, bool opaque, size_t len);

// Upper dir `name` (path[0..len)), walked against lower dir fd lfd or a
// LOWER_* sentinel. Takes ownership of lfd. Prints the dir's own line with
// `tag` first. tag 0 means the dir is unchanged unless its xattrs differ.
static void walk_dir(int ufd, const char *name, mode_t mode, int lfd, char tag,
                     bool opaque, size_t len) {
  struct relax_entry r;
  bool relaxed = relax(&r, ufd, name, mode, S_IRUSR | S_IXUSR);

  int fd = open_dir(ufd, name);
  if (fd < 0)
    err(1, "open upper %s", where());
  if (!tag && lfd >= 0 && xattrs_differ(fd, lfd))
    tag = 'M';
  if (tag)
    emit(tag, S_IFDIR, -1, name, fd);
  walk(fd, lfd, opaque || is_opaque(fd), descend(len));
  path[len] = '\0';
  if (close(fd) < 0 || (lfd >= 0 && close(lfd) < 0))
    err(1, "close %s", where());
  if (relaxed)
    restore();
}

// Prints the line for upper non-dir entry `name`. A regular file is opened
// (relaxed if locked) so its xattrs can be listed. Other types aren't
// opened: a fifo open would block.
static void emit_upper(char tag, int ufd, const char *name,
                       const struct stat *u) {
  if (!S_ISREG(u->st_mode)) {
    emit(tag, u->st_mode, ufd, name, -1);
    return;
  }
  struct relax_entry r;
  bool relaxed = relax(&r, ufd, name, u->st_mode, S_IRUSR);
  int fd = openat(ufd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    err(1, "open upper %s", where());
  emit(tag, u->st_mode, ufd, name, fd);
  if (close(fd) < 0)
    err(1, "close %s", where());
  if (relaxed)
    restore();
}

// One upper entry `name` (path[0..len)) of a dir whose lower side is lfd.
static void walk_entry(int ufd, int lfd, bool opaque, const char *name,
                       size_t len) {
  struct stat u, l;

  if (fstatat(ufd, name, &u, AT_SYMLINK_NOFOLLOW) < 0)
    err(1, "stat upper %s", where());
  enum lookup found = lookup(lfd, name, &l);

  if (is_whiteout(&u)) {
    if (found == LOOKUP_PRESENT)
      gone_name(lfd, name, len);
    else if (found == LOOKUP_UNREADABLE)
      emit('?', 0, -1, name, -1);
    return;
  }

  if (S_ISDIR(u.st_mode)) {
    int sub = LOWER_NONE;
    char tag = 0;
    if (found == LOOKUP_ABSENT) {
      tag = 'A';
    } else if (found == LOOKUP_UNREADABLE) {
      tag = '?';
      sub = LOWER_UNREADABLE;
    } else if (!S_ISDIR(l.st_mode)) {
      tag = 'M'; // type change: non-dir became a dir
    } else {
      sub = open_lower_dir(lfd, name);
      if (sub == LOWER_UNREADABLE)
        tag = '?';
      else if (mode_differs(&u, &l))
        tag = 'M';
    }
    walk_dir(ufd, name, u.st_mode, sub, tag, opaque, len);
    return;
  }

  if (found == LOOKUP_ABSENT) {
    emit_upper('A', ufd, name, &u);
  } else if (found == LOOKUP_UNREADABLE) {
    emit_upper('?', ufd, name, &u);
  } else if ((u.st_mode ^ l.st_mode) & S_IFMT) {
    emit_upper('M', ufd, name, &u); // type change
    if (S_ISDIR(l.st_mode))
      gone_children(lfd, name, len);
  } else {
    switch (compare(ufd, lfd, name, &u, &l)) {
    case CMP_CHANGED:
      emit_upper('M', ufd, name, &u);
      break;
    case CMP_UNREADABLE:
      emit_upper('?', ufd, name, &u);
      break;
    case CMP_SAME:
      break;
    }
  }
}

// Merge-walks one directory level. Upper entries are always visited. In an
// opaque dir, lower entries with no upper counterpart are also deletions.
static void walk(int ufd, int lfd, bool opaque, size_t len) {
  struct dirent **u, **l = nullptr;
  int nu = list(ufd, "upper", &u), nl = 0;

  if (opaque && lfd >= 0)
    nl = list(lfd, "workspace", &l);
  for (int i = 0, j = 0; i < nu || j < nl;) {
    int c = i == nu ? 1 : j == nl ? -1 : strcmp(u[i]->d_name, l[j]->d_name);
    if (c > 0) {
      const char *name = l[j++]->d_name;
      gone_name(lfd, name, push(len, name));
      continue;
    }
    if (c == 0)
      j++;
    const char *name = u[i++]->d_name;
    walk_entry(ufd, lfd, opaque, name, push(len, name));
  }
  path[len] = '\0';
  free_list(u, nu);
  if (l)
    free_list(l, nl);
}

bool diff_print(const struct run *run, const char *ws) {
  struct stat u, l;

  if (atexit(restore_all) != 0)
    errx(1, "atexit");

  // Open upper via the run dir so a chmod'ed upper root can be relaxed.
  int pfd = open(run->dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (pfd < 0)
    err(1, "open %s", run->dir);
  if (fstatat(pfd, "upper", &u, AT_SYMLINK_NOFOLLOW) < 0)
    err(1, "stat %s", run->upper);

  // overlay_prepare gave upper the workspace root's mode, so a difference
  // here is the agent's chmod of the root.
  char tag = 0;
  int lfd = open_lower_dir(AT_FDCWD, ws);
  if (lfd == LOWER_UNREADABLE) {
    tag = '?';
  } else {
    if (fstat(lfd, &l) < 0)
      err(1, "stat %s", ws);
    if (mode_differs(&u, &l))
      tag = 'M';
  }
  walk_dir(pfd, "upper", u.st_mode, lfd, tag, false, 0);
  if (close(pfd) < 0)
    err(1, "close %s", run->dir);
  if (fflush(stdout) == EOF)
    err(1, "fflush stdout");
  return complete;
}
