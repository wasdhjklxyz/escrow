#include "diff.h"

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;

struct walk {
  FILE *out;
  char path[PATH_MAX]; /* relative to the workspace root */
  size_t len;
};

static size_t push(struct walk *w, const char *name) {
  size_t old = w->len;
  int n = snprintf(w->path + old, sizeof w->path - old, "%s%s",
                   old == 0 ? "" : "/", name);
  if (n < 0 || (size_t)n >= sizeof w->path - old)
    errx(1, "path too long: %s/%s", w->path, name);
  w->len += (size_t)n;
  return old;
}

static void pop(struct walk *w, size_t old) {
  w->len = old;
  w->path[old] = '\0';
}

/* Paths are agent-controlled: escape control bytes and '\' so a crafted
 * name (e.g. containing "\nD foo") can't forge diff lines. */
static void emit(struct walk *w, char tag, mode_t mode) {
  if (fprintf(w->out, "%c ", tag) < 0)
    err(1, "write diff");
  for (const unsigned char *p = (const unsigned char *)w->path; *p; p++) {
    int r;
    if (*p == '\\')
      r = fputs("\\\\", w->out);
    else if (*p < 0x20 || *p == 0x7f)
      r = fprintf(w->out, "\\x%02x", *p);
    else
      r = fputc(*p, w->out);
    if (r < 0)
      err(1, "write diff");
  }
  const char *suffix = "";
  if (S_ISDIR(mode))
    suffix = "/";
  else if (S_ISFIFO(mode))
    suffix = " (fifo)";
  else if (S_ISSOCK(mode))
    suffix = " (socket)";
  else if (S_ISCHR(mode))
    suffix = " (char device)";
  else if (S_ISBLK(mode))
    suffix = " (block device)";
  if (fprintf(w->out, "%s\n", suffix) < 0)
    err(1, "write diff");
}

static void xclose(int fd) {
  if (close(fd) < 0)
    err(1, "close");
}

static int open_dir(int dfd, const char *name, const struct walk *w) {
  int fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    err(1, "open %s", w->path);
  return fd;
}

/* Lower (workspace) dir; we may not chmod it. If the host user can't read
 * it, mark it "?" (contents not compared) and return -1 instead of dying:
 * the agent could enter it via CAP_DAC_OVERRIDE in its userns. */
static int open_lower_dir(int dfd, const char *name, struct walk *w) {
  int fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd >= 0)
    return fd;
  if (errno != EACCES)
    err(1, "open %s", w->path);
  warn("workspace dir %s not compared", w->path);
  emit(w, '?', S_IFDIR);
  return -1;
}

/*
 * Upper entries belong to our uid, but the agent had CAP_DAC_OVERRIDE in its
 * userns and we don't: a dir it chmod'ed 000 would abort the walk. Add u+rx
 * for the walk, then restore the agent's mode. Relaxed dirs are always
 * ancestors of the walk position, so they form a stack; restore_relaxed()
 * also runs at exit, so an err() mid-walk never leaves upper altered.
 */
static struct {
  int dfd;
  const char *name; /* owned by the enclosing dir's listing (or caller) */
  mode_t mode;
} relaxed[PATH_MAX / 2 + 1];
static size_t n_relaxed;

static void restore_relaxed(void) {
  while (n_relaxed > 0) {
    n_relaxed--;
    if (fchmodat(relaxed[n_relaxed].dfd, relaxed[n_relaxed].name,
                 relaxed[n_relaxed].mode, AT_SYMLINK_NOFOLLOW) < 0)
      warn("restore mode of %s in upper", relaxed[n_relaxed].name);
  }
}

static int open_upper_dir(int dfd, const char *name, mode_t mode,
                          const struct walk *w) {
  mode_t perm = mode & 07777;
  if ((perm & (S_IRUSR | S_IXUSR)) == (S_IRUSR | S_IXUSR))
    return open_dir(dfd, name, w);
  if (n_relaxed == sizeof relaxed / sizeof *relaxed)
    errx(1, "too deep: %s", w->path);
  /* Recorded before the chmod, so a failure anywhere after is restored. */
  relaxed[n_relaxed++] = (typeof(*relaxed)){dfd, name, perm};
  if (fchmodat(dfd, name, perm | S_IRUSR | S_IXUSR, AT_SYMLINK_NOFOLLOW) < 0)
    err(1, "chmod u+rx %s", w->len ? w->path : name);
  return open_dir(dfd, name, w);
}

static void close_upper_dir(int fd, mode_t mode, const struct walk *w) {
  mode_t perm = mode & 07777;
  if ((perm & (S_IRUSR | S_IXUSR)) != (S_IRUSR | S_IXUSR)) {
    if (fchmod(fd, perm) < 0)
      err(1, "restore mode %s", w->path);
    n_relaxed--;
  }
  xclose(fd);
}

/* lstat relative to dfd; 0 if absent. */
static int lstat_at(int dfd, const char *name, struct stat *st,
                    const struct walk *w) {
  if (fstatat(dfd, name, st, AT_SYMLINK_NOFOLLOW) == 0)
    return 1;
  if (errno == ENOENT || errno == ENOTDIR)
    return 0;
  err(1, "stat %s", w->path);
}

static int not_dots(const struct dirent *d) {
  return strcmp(d->d_name, ".") != 0 && strcmp(d->d_name, "..") != 0;
}

/* strcmp, not alphasort: alphasort is strcoll (locale-dependent order). */
static int by_name(const struct dirent **a, const struct dirent **b) {
  return strcmp((*a)->d_name, (*b)->d_name);
}

static int list_dir(int dfd, struct dirent ***names, const struct walk *w) {
  int n = scandirat(dfd, ".", names, not_dots, by_name);
  if (n < 0)
    err(1, "scandir %s", w->len ? w->path : ".");
  return n;
}

static void free_list(struct dirent **names, int n) {
  for (int i = 0; i < n; i++)
    free(names[i]);
  free(names);
}

static int is_whiteout(const struct stat *st) {
  return S_ISCHR(st->st_mode) && st->st_rdev == makedev(0, 0);
}

/* "user.overlay.opaque" == "y" (userxattr mount). "x" marks a dir holding
 * xattr whiteouts and is not opaque. */
static int is_opaque(int fd, const struct walk *w) {
  char v[2];
  ssize_t n = fgetxattr(fd, "user.overlay.opaque", v, sizeof v);
  if (n < 0) {
    if (errno == ENODATA)
      return 0;
    err(1, "getxattr user.overlay.opaque %s", w->path);
  }
  return n == 1 && v[0] == 'y';
}

/* Print D for everything below lower dir fd. */
static void deleted_tree(struct walk *w, int fd) {
  struct dirent **names;
  int n = list_dir(fd, &names, w);
  for (int i = 0; i < n; i++) {
    size_t old = push(w, names[i]->d_name);
    struct stat st;
    if (lstat_at(fd, names[i]->d_name, &st, w)) {
      emit(w, 'D', st.st_mode);
      int sub;
      if (S_ISDIR(st.st_mode) &&
          (sub = open_lower_dir(fd, names[i]->d_name, w)) >= 0) {
        deleted_tree(w, sub);
        xclose(sub);
      }
    }
    pop(w, old);
  }
  free_list(names, n);
}

static void deleted(struct walk *w, int lfd, const char *name,
                    const struct stat *ls) {
  emit(w, 'D', ls->st_mode);
  int sub;
  if (S_ISDIR(ls->st_mode) && (sub = open_lower_dir(lfd, name, w)) >= 0) {
    deleted_tree(w, sub);
    xclose(sub);
  }
}

static size_t read_full(int fd, char *buf, size_t len, const struct walk *w) {
  size_t got = 0;
  while (got < len) {
    ssize_t n = read(fd, buf + got, len - got);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      err(1, "read %s", w->path);
    }
    if (n == 0)
      break;
    got += (size_t)n;
  }
  return got;
}

/* 1 if upper and lower regular files have identical bytes. A lower file the
 * host user can't read counts as different: over-reporting is safe,
 * under-reporting isn't. */
static int same_bytes(int ufd, int lfd, const char *name,
                      const struct walk *w) {
  int u = openat(ufd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (u < 0)
    err(1, "open upper %s", w->path);
  int l = openat(lfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (l < 0) {
    if (errno != EACCES)
      err(1, "open lower %s", w->path);
    xclose(u);
    return 0;
  }
  static char ub[1 << 16], lb[1 << 16];
  int same = 1;
  for (;;) {
    size_t un = read_full(u, ub, sizeof ub, w);
    size_t ln = read_full(l, lb, sizeof lb, w);
    if (un != ln || memcmp(ub, lb, un) != 0) {
      same = 0;
      break;
    }
    if (un == 0)
      break;
  }
  xclose(u);
  xclose(l);
  return same;
}

static int same_link(int ufd, int lfd, const char *name, const struct walk *w) {
  char ub[PATH_MAX], lb[PATH_MAX];
  ssize_t un = readlinkat(ufd, name, ub, sizeof ub);
  if (un < 0)
    err(1, "readlink upper %s", w->path);
  ssize_t ln = readlinkat(lfd, name, lb, sizeof lb);
  if (ln < 0)
    err(1, "readlink lower %s", w->path);
  if ((size_t)un == sizeof ub || (size_t)ln == sizeof lb)
    errx(1, "symlink target too long: %s", w->path);
  return un == ln && memcmp(ub, lb, (size_t)un) == 0;
}

/* Same type, mode and content? Suppresses no-op copy-ups. */
static int unchanged(int ufd, int lfd, const char *name, const struct stat *us,
                     const struct stat *ls, const struct walk *w) {
  if (us->st_mode != ls->st_mode)
    return 0;
  /* Same mode without u+r: we can't read either side, so report it. */
  if (S_ISREG(us->st_mode) && !(us->st_mode & S_IRUSR))
    return 0;
  if (S_ISREG(us->st_mode))
    return us->st_size == ls->st_size && same_bytes(ufd, lfd, name, w);
  if (S_ISLNK(us->st_mode))
    return same_link(ufd, lfd, name, w);
  if (S_ISCHR(us->st_mode) || S_ISBLK(us->st_mode))
    return us->st_rdev == ls->st_rdev;
  return 1;
}

static void walk_dir(struct walk *w, int ufd, int lfd, int opaque);

/* One upper entry against its lower counterpart (if lfd >= 0). */
static void walk_entry(struct walk *w, int ufd, int lfd, int opaque,
                       const char *name) {
  struct stat us, ls;
  if (!lstat_at(ufd, name, &us, w))
    errx(1, "%s vanished from upper", w->path);
  int has_lower = lfd >= 0 && lstat_at(lfd, name, &ls, w);

  if (is_whiteout(&us)) {
    if (has_lower)
      deleted(w, lfd, name, &ls);
  } else if (S_ISDIR(us.st_mode)) {
    int sub = open_upper_dir(ufd, name, us.st_mode, w);
    int sub_opaque = opaque || is_opaque(sub, w);
    if (has_lower && S_ISDIR(ls.st_mode)) {
      if (us.st_mode != ls.st_mode)
        emit(w, 'M', us.st_mode);
      /* Unreadable lower: already marked "?", entries below show as A. */
      int lsub = open_lower_dir(lfd, name, w);
      walk_dir(w, sub, lsub, lsub >= 0 && sub_opaque);
      if (lsub >= 0)
        xclose(lsub);
    } else {
      if (has_lower)
        deleted(w, lfd, name, &ls);
      emit(w, 'A', us.st_mode);
      walk_dir(w, sub, -1, 0);
    }
    close_upper_dir(sub, us.st_mode, w);
  } else if (!has_lower) {
    emit(w, 'A', us.st_mode);
  } else if (S_ISDIR(ls.st_mode)) {
    deleted(w, lfd, name, &ls);
    emit(w, 'A', us.st_mode);
  } else if (!unchanged(ufd, lfd, name, &us, &ls, w)) {
    emit(w, 'M', us.st_mode);
  }
}

/*
 * ufd: upper dir. lfd: matching lower dir, or -1 if none (everything is A).
 * opaque: overlay stopped lower lookups at or above this dir, so lower
 * entries missing from upper are deletions. Both listings are sorted and
 * merged so output order is one total order per directory.
 */
static void walk_dir(struct walk *w, int ufd, int lfd, int opaque) {
  struct dirent **un, **ln = NULL;
  int nu = list_dir(ufd, &un, w), nl = 0;
  if (opaque && lfd >= 0)
    nl = list_dir(lfd, &ln, w);

  for (int i = 0, j = 0; i < nu || j < nl;) {
    if (interrupted)
      errx(1, "interrupted; upper modes restored");
    int c = i >= nu ? 1 : j >= nl ? -1 : strcmp(un[i]->d_name, ln[j]->d_name);
    const char *name = c <= 0 ? un[i]->d_name : ln[j]->d_name;
    size_t old = push(w, name);
    if (c <= 0) {
      walk_entry(w, ufd, lfd, opaque, name);
    } else {
      struct stat ls; /* lower only, hidden by the opaque dir */
      if (lstat_at(lfd, name, &ls, w))
        deleted(w, lfd, name, &ls);
    }
    pop(w, old);
    i += c <= 0;
    j += c >= 0;
  }
  free_list(un, nu);
  if (ln != NULL)
    free_list(ln, nl);
}

static void on_signal(int sig) {
  (void)sig;
  interrupted = 1;
}

void diff_print(const char *upper, const char *lower, FILE *out) {
  struct walk w = {.out = out};

  /* Relaxed upper modes must be restored however the walk ends: err() goes
   * through exit() -> atexit; signals set a flag the walk checks. SIGKILL
   * can't be caught. */
  if (atexit(restore_relaxed) != 0)
    errx(1, "atexit");
  struct sigaction sa = {.sa_handler = on_signal};
  if (sigemptyset(&sa.sa_mask) < 0)
    err(1, "sigemptyset");
  const int sigs[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM};
  for (size_t i = 0; i < sizeof sigs / sizeof *sigs; i++)
    if (sigaction(sigs[i], &sa, NULL) < 0)
      err(1, "sigaction %d", sigs[i]);

  /* chmod on the merged root lands on the upper root. */
  struct stat us;
  if (lstat(upper, &us) < 0)
    err(1, "stat %s", upper);
  int ufd = open_upper_dir(AT_FDCWD, upper, us.st_mode, &w);
  int lfd = open(lower, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (lfd < 0)
    err(1, "open %s", lower);
  walk_dir(&w, ufd, lfd, 0);
  close_upper_dir(ufd, us.st_mode, &w);
  xclose(lfd);
  if (fflush(out) == EOF)
    err(1, "write diff");
}
