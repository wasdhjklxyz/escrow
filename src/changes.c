#include "changes.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#define MAGIC "escrow-changes 1\n"

static void wfail(struct changes_writer *w, const char *fmt, const char *path) {
  if (!w->ok)
    return;
  w->ok = false;
  snprintf(w->why, sizeof w->why, fmt, *path ? path : ".");
}

static void put(struct changes_writer *w, const void *buf, size_t n) {
  if (n && fwrite(buf, 1, n, w->f) != n)
    err(1, "write change set");
}

static void header(struct changes_writer *w, char op, mode_t mode,
                   const char *path, size_t datalen) {
  if (fprintf(w->f, "%c %o %zu %zu\n", op, (unsigned)(mode & 07777),
              strlen(path), datalen) < 0)
    err(1, "write change set");
  put(w, path, strlen(path));
}

// user.* xattrs of fd. Overlay's own (user.overlay.*, trusted.overlay.*)
// are skipped, as in diff.c. Anything else can't be set back unprivileged.
static void put_xattrs(struct changes_writer *w, int fd, const char *path) {
  static char names[XATTR_LIST_MAX], val[XATTR_SIZE_MAX];

  if (fd < 0)
    return;
  ssize_t n = flistxattr(fd, names, sizeof names);
  if (n < 0)
    err(1, "listxattr %s", path);
  for (char *p = names; p < names + n; p += strlen(p) + 1) {
    if (strncmp(p, "user.overlay.", 13) == 0)
      continue; // overlay's own (trusted.* is invisible unprivileged)
    if (strncmp(p, "user.", 5) != 0) {
      wfail(w, "%s: carries a non-user xattr", path);
      continue;
    }
    ssize_t vl = fgetxattr(fd, p, val, sizeof val);
    if (vl < 0)
      err(1, "getxattr %s %s", path, p);
    if (fprintf(w->f, "x %zu %zd\n", strlen(p), vl) < 0)
      err(1, "write change set");
    put(w, p, strlen(p));
    put(w, val, (size_t)vl);
  }
}

static bool under(const char *path, const char *dir) {
  size_t n = strlen(dir);
  return strncmp(path, dir, n) == 0 && path[n] == '/';
}

void changes_open(struct changes_writer *w, const char *file) {
  *w = (struct changes_writer){.ok = true};
  int fd =
      open(file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0 || !(w->f = fdopen(fd, "w")))
    err(1, "open %s", file);
  put(w, MAGIC, strlen(MAGIC));
}

void changes_emit(struct changes_writer *w, char tag, mode_t mode,
                  const char *path, int dirfd, const char *name, int fd) {
  struct stat st;

  if (tag == '?') {
    wfail(w, "%s: could not be compared", path);
    return;
  }
  if (w->covered[0] && under(path, w->covered))
    return; // below a path already deleted or replaced
  if (tag == 'D') {
    header(w, 'D', 0, path, 0);
    put(w, "e\n", 2);
    snprintf(w->covered, sizeof w->covered, "%s", path);
    return;
  }
  // diff.c passes only S_IFDIR for dirs: take the real bits from the fd.
  if (fd >= 0) {
    if (fstat(fd, &st) < 0)
      err(1, "fstat %s", path);
    mode = st.st_mode;
  }
  if (mode & (S_ISUID | S_ISGID) || (mode & S_ISVTX && !S_ISDIR(mode))) {
    wfail(w, "%s: set-id or sticky bit", path);
    return;
  }
  if (S_ISDIR(mode)) {
    header(w, *path ? 'd' : 'r', mode, path, 0);
    put_xattrs(w, fd, path);
  } else if (S_ISREG(mode)) {
    static char buf[1 << 16];
    off_t off = 0;
    ssize_t n;
    header(w, 'f', mode, path, (size_t)st.st_size);
    while ((n = pread(fd, buf, sizeof buf, off)) != 0) {
      if (n < 0) {
        if (errno == EINTR)
          continue;
        err(1, "read %s", path);
      }
      if (off + n > st.st_size)
        errx(1, "%s grew while being recorded", path);
      put(w, buf, (size_t)n);
      off += n;
    }
    if (off != st.st_size)
      errx(1, "%s shrank while being recorded", path);
    put_xattrs(w, fd, path);
  } else if (S_ISLNK(mode)) {
    char target[PATH_MAX];
    ssize_t n = readlinkat(dirfd, name, target, sizeof target);
    if (n < 0 || (size_t)n >= sizeof target)
      err(1, "readlink %s", path);
    header(w, 'l', 0777, path, (size_t)n);
    put(w, target, (size_t)n);
  } else if (S_ISFIFO(mode)) {
    header(w, 'p', mode, path, 0);
  } else {
    wfail(w, "%s: socket or device can't be proposed", path);
    return;
  }
  put(w, "e\n", 2);
  if (!S_ISDIR(mode)) {
    snprintf(w->covered, sizeof w->covered, "%s", path);
  }
}

bool changes_close(struct changes_writer *w) {
  if (fflush(w->f) == EOF || fsync(fileno(w->f)) < 0 || fclose(w->f) == EOF)
    err(1, "close change set");
  return w->ok;
}

int changes_path_cmp(const char *a, const char *b) {
  while (*a && *b) {
    size_t la = strcspn(a, "/"), lb = strcspn(b, "/");
    int c = memcmp(a, b, la < lb ? la : lb);
    if (c)
      return c;
    if (la != lb)
      return la < lb ? -1 : 1; // as strcmp: a prefix sorts first
    a += la;
    b += lb;
    a += *a == '/';
    b += *b == '/';
  }
  return (*a != '\0') - (*b != '\0'); // an ancestor sorts first
}

static bool path_ok(const char *p, size_t len) {
  if (len == 0 || strlen(p) != len || p[0] == '/' || p[len - 1] == '/')
    return false;
  for (const char *c = p; *c;) {
    size_t n = strcspn(c, "/");
    if (n == 0 || (n == 1 && c[0] == '.') ||
        (n == 2 && c[0] == '.' && c[1] == '.'))
      return false;
    c += n;
    if (*c)
      c++;
  }
  return true;
}

struct reader {
  const char *file;
  char *buf;
  size_t len, pos;
};

[[noreturn]] static void bad(const struct reader *r, const char *what) {
  errx(1, "%s: malformed change set at byte %zu: %s", r->file, r->pos, what);
}

static void take(struct reader *r, size_t n, char **out) {
  if (n > r->len - r->pos)
    bad(r, "truncated");
  if (!(*out = malloc(n + 1)))
    err(1, "malloc");
  memcpy(*out, r->buf + r->pos, n);
  (*out)[n] = '\0';
  r->pos += n;
}

// One "\n"-terminated header line, at most 80 bytes.
static const char *line(struct reader *r) {
  static char l[81];
  const char *nl = memchr(r->buf + r->pos, '\n', r->len - r->pos);
  if (!nl || (size_t)(nl - (r->buf + r->pos)) >= sizeof l)
    bad(r, "bad header line");
  size_t n = (size_t)(nl - (r->buf + r->pos));
  memcpy(l, r->buf + r->pos, n);
  l[n] = '\0';
  r->pos += n + 1;
  return l;
}

void changes_read(const char *file, struct changeset *cs) {
  struct reader r = {.file = file};
  struct stat st;
  const char *prev = nullptr;

  *cs = (struct changeset){};
  int fd = open(file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0 || fstat(fd, &st) < 0)
    err(1, "open %s", file);
  r.len = (size_t)st.st_size;
  if (!(r.buf = malloc(r.len + 1)))
    err(1, "malloc");
  for (size_t got = 0; got < r.len;) {
    ssize_t n = read(fd, r.buf + got, r.len - got);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      n < 0 ? err(1, "read %s", file) : errx(1, "read %s: short read", file);
    got += (size_t)n;
  }
  close(fd);
  if (r.len < strlen(MAGIC) || memcmp(r.buf, MAGIC, strlen(MAGIC)) != 0)
    bad(&r, "not an escrow change set");
  r.pos = strlen(MAGIC);

  while (r.pos < r.len) {
    struct change c = {};
    unsigned mode;
    size_t plen, dlen;
    char op, tail;
    const char *hl = line(&r);
    char canon[96];
    if (sscanf(hl, "%c %o %zu %zu%c", &op, &mode, &plen, &dlen, &tail) != 4)
      bad(&r, "bad entry header");
    // Exactly what the writer emits: no "+644", leading zeros or extra
    // spaces, so one change set has one byte form.
    snprintf(canon, sizeof canon, "%c %o %zu %zu", op, mode, plen, dlen);
    if (strcmp(canon, hl) != 0)
      bad(&r, "non-canonical entry header");
    if (!strchr("rdflpD", op) || mode > 07777 || plen >= PATH_MAX)
      bad(&r, "bad op, mode or path length");
    c.op = op;
    c.mode = mode;
    take(&r, plen, &c.path);
    take(&r, dlen, &c.data);
    c.len = dlen;
    if (op == 'r' ? plen != 0 : !path_ok(c.path, plen))
      bad(&r, "bad path");
    if ((op != 'f' && op != 'l' && dlen) ||
        (op == 'l' && memchr(c.data, '\0', dlen)))
      bad(&r, "data on an entry that takes none");
    if (mode & (S_ISUID | S_ISGID) ||
        (mode & S_ISVTX && op != 'd' && op != 'r'))
      bad(&r, "set-id or sticky bit");
    if ((op == 'D' && mode != 0) || (op == 'l' && mode != 0777))
      bad(&r, "mode not canonical for this op");
    if (op == 'r' && cs->n)
      bad(&r, "root entry not first");
    if (prev && changes_path_cmp(prev, c.path) >= 0)
      bad(&r, "entries out of order or repeated");
    for (;;) {
      const char *l = line(&r);
      if (strcmp(l, "e") == 0)
        break;
      size_t nl, vl;
      char canon[64];
      if (op == 'D' || op == 'l' || op == 'p' ||
          sscanf(l, "x %zu %zu%c", &nl, &vl, &tail) != 2 || nl > 255 ||
          vl > XATTR_SIZE_MAX)
        bad(&r, "bad xattr line");
      snprintf(canon, sizeof canon, "x %zu %zu", nl, vl);
      if (strcmp(canon, l) != 0)
        bad(&r, "non-canonical xattr line");
      struct xattr *x = reallocarray(c.x, c.nx + 1, sizeof *x);
      if (!x)
        err(1, "reallocarray");
      c.x = x;
      take(&r, nl, &x[c.nx].name);
      take(&r, vl, &x[c.nx].value);
      x[c.nx].len = vl;
      if (strlen(x[c.nx].name) != nl || strncmp(x[c.nx].name, "user.", 5) ||
          !strncmp(x[c.nx].name, "user.overlay.", 13))
        bad(&r, "xattr not a plain user.* name");
      for (size_t j = 0; j < c.nx; j++)
        if (strcmp(x[j].name, x[c.nx].name) == 0)
          bad(&r, "xattr listed twice");
      c.nx++;
    }
    struct change *v = reallocarray(cs->v, cs->n + 1, sizeof *v);
    if (!v)
      err(1, "reallocarray");
    cs->v = v;
    cs->v[cs->n++] = c;
    prev = c.path;
  }
  free(r.buf);
}

void changes_free(struct changeset *cs) {
  for (size_t i = 0; i < cs->n; i++) {
    struct change *c = &cs->v[i];
    for (size_t j = 0; j < c->nx; j++) {
      free(c->x[j].name);
      free(c->x[j].value);
    }
    free(c->x);
    free(c->path);
    free(c->data);
  }
  free(cs->v);
  *cs = (struct changeset){};
}
