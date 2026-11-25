#include "overlay.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static void join(char out[PATH_MAX], const char *a, const char *b) {
  int n = snprintf(out, PATH_MAX, "%s/%s", a, b);
  if (n < 0 || n >= PATH_MAX)
    errx(1, "path too long: %s/%s", a, b);
}

/* Is path equal to or below dir? Both canonical. */
static int inside(const char *path, const char *dir) {
  size_t n = strlen(dir);
  if (n == 1 && dir[0] == '/')
    return 1;
  return strncmp(path, dir, n) == 0 && (path[n] == '/' || path[n] == '\0');
}

/*
 * Canonicalize a path that may not exist yet: realpath() the deepest existing
 * ancestor, then append the missing components. Those can't be symlinks
 * (they don't exist), but "." / ".." would defeat the overlap check, so they
 * are refused.
 */
static void resolve_missing(const char *in, char out[PATH_MAX]) {
  char head[PATH_MAX];
  if (snprintf(head, sizeof head, "%s", in) >= (int)sizeof head)
    errx(1, "path too long: %s", in);

  /* in[cut] is where the missing suffix starts ('/' or end of string). */
  size_t cut = strlen(head);
  while (realpath(head, out) == NULL) {
    if (errno != ENOENT)
      err(1, "realpath %s", head);
    char *slash = strrchr(head, '/');
    if (slash == NULL)
      errx(1, "not an absolute path: %s", in);
    cut = (size_t)(slash - head);
    if (slash == head) {
      memcpy(out, "/", 2);
      break;
    }
    *slash = '\0';
  }
  if (in[cut] == '\0')
    return;

  const char *rest = in + cut + 1;
  for (const char *c = rest; *c != '\0';) {
    size_t len = strcspn(c, "/");
    if ((len == 1 && c[0] == '.') || (len == 2 && c[0] == '.' && c[1] == '.'))
      errx(1, "state path must not contain . or ..: %s", in);
    c += len;
    c += strspn(c, "/");
  }
  char tmp[PATH_MAX];
  join(tmp, strcmp(out, "/") == 0 ? "" : out, rest);
  memcpy(out, tmp, PATH_MAX);
}

/* mkdir -p, 0700 for every created level. */
static void mkdir_p(const char *path) {
  char buf[PATH_MAX];
  if (snprintf(buf, sizeof buf, "%s", path) >= (int)sizeof buf)
    errx(1, "path too long: %s", path);
  for (char *p = buf + 1;; p++) {
    if (*p != '/' && *p != '\0')
      continue;
    char c = *p;
    *p = '\0';
    if (mkdir(buf, 0700) < 0 && errno != EEXIST)
      err(1, "mkdir %s", buf);
    *p = c;
    if (c == '\0')
      break;
  }
}

/* <state>/runs, made absolute against cwd (resolve_missing needs that). */
static void runs_dir(char out[PATH_MAX], const char *state) {
  char abs[PATH_MAX];
  if (state[0] == '/') {
    if (snprintf(abs, sizeof abs, "%s", state) >= (int)sizeof abs)
      errx(1, "path too long: %s", state);
  } else {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof cwd) == NULL)
      err(1, "getcwd");
    join(abs, cwd, state);
  }
  join(out, abs, "runs");
}

static void check_overlap(const char *run, const char *ws) {
  if (inside(run, ws))
    errx(1, "state dir %s is inside workspace %s", run, ws);
  if (inside(ws, run))
    errx(1, "workspace %s is inside state dir %s", ws, run);
}

void overlay_prepare(struct overlay *ov, const char *workspace,
                     const char *state) {
  if (realpath(workspace, ov->lower) == NULL)
    err(1, "realpath %s", workspace);
  struct stat st;
  if (stat(ov->lower, &st) < 0)
    err(1, "stat %s", ov->lower);
  if (!S_ISDIR(st.st_mode))
    errx(1, "workspace %s is not a directory", ov->lower);

  /* Check before creating anything, so a bad state path can't write into
   * the workspace. */
  char base[PATH_MAX], runs[PATH_MAX];
  runs_dir(base, state);
  resolve_missing(base, runs);
  check_overlap(runs, ov->lower);
  mkdir_p(runs);

  char tmpl[PATH_MAX];
  join(tmpl, runs, "XXXXXX");
  if (mkdtemp(tmpl) == NULL)
    err(1, "mkdtemp %s", tmpl);
  if (realpath(tmpl, ov->run) == NULL)
    err(1, "realpath %s", tmpl);
  /* Recheck the canonical result: runs may have changed under us. */
  check_overlap(ov->run, ov->lower);

  join(ov->upper, ov->run, "upper");
  join(ov->work, ov->run, "work");
  join(ov->merged, ov->run, "merged");
  const char *dirs[] = {ov->upper, ov->work, ov->merged};
  for (size_t i = 0; i < sizeof dirs / sizeof *dirs; i++)
    if (mkdir(dirs[i], 0700) < 0)
      err(1, "mkdir %s", dirs[i]);
}

/* Drain the fs context's message log ("e overlay: ...") to stderr. */
static void fs_log(int fsfd) {
  char buf[512];
  ssize_t n;
  while ((n = read(fsfd, buf, sizeof buf - 1)) > 0) {
    buf[n] = '\0';
    fprintf(stderr, "escrow: kernel: %s\n", buf);
  }
}

static int fs_fail(int fsfd, const char *what, const char *arg) {
  int e = errno;
  fs_log(fsfd);
  errno = e;
  warn("%s %s", what, arg);
  close(fsfd);
  return -1;
}

int overlay_mount(const struct overlay *ov) {
  int fsfd = fsopen("overlay", FSOPEN_CLOEXEC);
  if (fsfd < 0) {
    warn("fsopen overlay");
    return -1;
  }
  if (fsconfig(fsfd, FSCONFIG_SET_STRING, "lowerdir+", ov->lower, 0) < 0)
    return fs_fail(fsfd, "fsconfig lowerdir+", ov->lower);
  if (fsconfig(fsfd, FSCONFIG_SET_STRING, "upperdir", ov->upper, 0) < 0)
    return fs_fail(fsfd, "fsconfig upperdir", ov->upper);
  if (fsconfig(fsfd, FSCONFIG_SET_STRING, "workdir", ov->work, 0) < 0)
    return fs_fail(fsfd, "fsconfig workdir", ov->work);
  if (fsconfig(fsfd, FSCONFIG_SET_FLAG, "userxattr", NULL, 0) < 0)
    return fs_fail(fsfd, "fsconfig", "userxattr");
  if (fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0)
    return fs_fail(fsfd, "fsconfig", "create");

  int mfd =
      fsmount(fsfd, FSMOUNT_CLOEXEC, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV);
  if (mfd < 0)
    return fs_fail(fsfd, "fsmount", "overlay");
  if (close(fsfd) < 0) {
    warn("close fs context");
    close(mfd);
    return -1;
  }
  if (move_mount(mfd, "", AT_FDCWD, ov->merged, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
    warn("move_mount %s", ov->merged);
    close(mfd);
    return -1;
  }
  if (close(mfd) < 0) {
    warn("close mount fd");
    return -1;
  }
  return 0;
}
