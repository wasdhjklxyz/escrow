#include "jail.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

/* Child-side failure: _exit, never exit, so stdio buffers duplicated by
 * fork() aren't flushed twice and atexit handlers don't run. */
[[noreturn]] static void child_fail(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vwarn(fmt, ap);
  va_end(ap);
  _exit(JAIL_ESETUP);
}

/* The kernel requires each id map in a single write(). */
static void write_once(const char *path, const char *buf) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    child_fail("open %s", path);
  size_t len = strlen(buf);
  ssize_t n = write(fd, buf, len);
  if (n < 0)
    child_fail("write %s", path);
  if ((size_t)n != len) {
    warnx("write %s: short write (%zd of %zu)", path, n, len);
    _exit(JAIL_ESETUP);
  }
  if (close(fd) < 0)
    child_fail("close %s", path);
}

static void write_map(const char *path, unsigned id) {
  char map[32];
  int n = snprintf(map, sizeof map, "0 %u 1\n", id);
  if (n < 0 || (size_t)n >= sizeof map) {
    warnx("format %s", path);
    _exit(JAIL_ESETUP);
  }
  write_once(path, map);
}

[[noreturn]] static void child(const struct overlay *ov, uid_t uid, gid_t gid,
                               char *const argv[]) {
  /* Fresh child of a single-threaded parent, so unshare can't hit EINVAL. */
  if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0)
    child_fail("unshare(CLONE_NEWUSER|CLONE_NEWNS)");

  /* setgroups must be denied before an unprivileged gid_map write. */
  write_once("/proc/self/setgroups", "deny");
  write_map("/proc/self/uid_map", uid);
  write_map("/proc/self/gid_map", gid);

  /* Before any mount: stop propagation in both directions. */
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
    child_fail("mount / MS_REC|MS_PRIVATE");

  if (overlay_mount(ov) < 0)
    _exit(JAIL_ESETUP);
  if (chdir(ov->merged) < 0)
    child_fail("chdir %s", ov->merged);

  execvp(argv[0], argv);
  int e = errno;
  warn("exec %s", argv[0]);
  _exit(e == ENOENT ? JAIL_ENOENT : JAIL_ENOEXEC);
}

static struct sigaction old_int, old_quit;

pid_t jail_spawn(const struct overlay *ov, char *const argv[]) {
  /* Must be read before unshare: inside the new userns, until the maps are
   * written, these return the overflow id (65534). */
  uid_t uid = getuid();
  gid_t gid = getgid();

  /* Orphaned descendants of the agent reparent to us instead of init, so
   * jail_wait can kill and reap them before the diff. Not inherited. */
  if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0)
    err(1, "prctl(PR_SET_CHILD_SUBREAPER)");

  if (fflush(NULL) == EOF)
    err(1, "fflush");
  pid_t pid = fork();
  if (pid < 0)
    err(1, "fork");
  if (pid == 0)
    child(ov, uid, gid, argv);

  /* After fork, so the child doesn't inherit SIG_IGN across execve: ^C kills
   * the agent, the parent survives to print the diff. */
  struct sigaction sa = {.sa_handler = SIG_IGN};
  if (sigemptyset(&sa.sa_mask) < 0)
    err(1, "sigemptyset");
  if (sigaction(SIGINT, &sa, &old_int) < 0)
    err(1, "sigaction SIGINT");
  if (sigaction(SIGQUIT, &sa, &old_quit) < 0)
    err(1, "sigaction SIGQUIT");
  return pid;
}

/* SIGKILL every current child (agent leftovers reparented to us). */
static void kill_children(void) {
  char path[64];
  int n =
      snprintf(path, sizeof path, "/proc/self/task/%d/children", (int)getpid());
  if (n < 0 || (size_t)n >= sizeof path)
    errx(1, "format children path");
  FILE *f = fopen(path, "re");
  if (f == NULL)
    err(1, "open %s", path);
  long p;
  while (fscanf(f, "%ld", &p) == 1)
    if (kill((pid_t)p, SIGKILL) < 0 && errno != ESRCH)
      err(1, "kill %ld", p);
  if (ferror(f))
    err(1, "read %s", path);
  if (fclose(f) == EOF)
    err(1, "close %s", path);
}

/*
 * The change set is frozen when the agent exits: anything it left running
 * is killed and reaped, so nothing writes to upper after (or during) the
 * diff. Each reap can reparent grandchildren to us, hence the loop.
 */
static void reap_rest(void) {
  for (;;) {
    kill_children();
    if (waitpid(-1, NULL, 0) < 0) {
      if (errno == ECHILD)
        return;
      if (errno != EINTR)
        err(1, "waitpid");
    }
  }
}

int jail_wait(pid_t pid) {
  int st;
  while (waitpid(pid, &st, 0) < 0)
    if (errno != EINTR)
      err(1, "waitpid %d", (int)pid);
  reap_rest();
  if (sigaction(SIGINT, &old_int, NULL) < 0)
    err(1, "sigaction SIGINT");
  if (sigaction(SIGQUIT, &old_quit, NULL) < 0)
    err(1, "sigaction SIGQUIT");
  if (WIFEXITED(st))
    return WEXITSTATUS(st);
  if (WIFSIGNALED(st))
    return 128 + WTERMSIG(st);
  errx(1, "waitpid %d: unexpected status %#x", (int)pid, st);
}
