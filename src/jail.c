#include "jail.h"

#include "overlay.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

// The kernel parses each of these files from a single write().
static int write_file(const char *path, const char *buf) {
  size_t len = strlen(buf);

  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    warn("open %s", path);
    return -1;
  }
  ssize_t n = write(fd, buf, len);
  if (n < 0 || (size_t)n != len) {
    if (n < 0)
      warn("write %s", path);
    else
      warnx("write %s: short write", path);
    close(fd);
    return -1;
  }
  if (close(fd) < 0) {
    warn("close %s", path);
    return -1;
  }
  return 0;
}

// Child only. Afterwards we are root in a new user ns (mapped to the
// caller's uid/gid) and own a private mount ns.
static int enter_ns(uid_t uid, gid_t gid) {
  char map[64];

  if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
    warn("unshare");
    return -1;
  }
  // setgroups must be denied before an unprivileged gid_map write.
  if (write_file("/proc/self/setgroups", "deny") < 0)
    return -1;
  snprintf(map, sizeof map, "0 %u 1\n", uid);
  if (write_file("/proc/self/uid_map", map) < 0)
    return -1;
  snprintf(map, sizeof map, "0 %u 1\n", gid);
  if (write_file("/proc/self/gid_map", map) < 0)
    return -1;
  // Before any other mount: stop host mount events propagating in.
  if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) {
    warn("mount / private");
    return -1;
  }
  return 0;
}

[[noreturn]] static void child(const struct run *run, const char *ws,
                               char *const argv[], uid_t uid, gid_t gid) {
  if (enter_ns(uid, gid) < 0 || overlay_mount(run, ws) < 0)
    _exit(JAIL_SETUP_FAILED);
  if (chdir(run->merged) < 0) {
    warn("chdir %s", run->merged);
    _exit(JAIL_SETUP_FAILED);
  }
  execvp(argv[0], argv);
  warn("exec %s", argv[0]);
  _exit(127);
}

// We are the agent's subreaper, so anything it left running was
// reparented to us. SIGKILL whatever is listed, reap, repeat until no
// children remain. The children file can miss a process mid-reparent, so
// an empty list polls (WNOHANG) instead of blocking on a live child we
// never signalled.
static void reap_all(void) {
  char path[64];

  snprintf(path, sizeof path, "/proc/self/task/%d/children", (int)getpid());
  for (;;) {
    FILE *f = fopen(path, "re");
    if (!f)
      err(1, "%s", path);
    int pid, n = 0;
    while (fscanf(f, "%d", &pid) == 1) {
      // Our unreaped child: the pid can't have been recycled.
      if (kill(pid, SIGKILL) < 0 && errno != ESRCH)
        err(1, "kill %d", pid);
      n++;
    }
    if (ferror(f))
      err(1, "read %s", path);
    if (fclose(f) == EOF)
      err(1, "close %s", path);

    if (waitpid(-1, nullptr, n ? 0 : WNOHANG) < 0) {
      if (errno == ECHILD)
        return;
      if (errno != EINTR)
        err(1, "waitpid");
    }
  }
}

int jail_run(const struct run *run, const char *ws, char *const argv[]) {
  // The map must name our ids as the host sees them.
  uid_t uid = getuid();
  gid_t gid = getgid();
  struct sigaction sa = {.sa_handler = SIG_DFL};
  int st;

  // An inherited SIG_IGN for SIGCHLD makes the kernel auto-reap children,
  // and waitpid would fail with ECHILD.
  if (sigaction(SIGCHLD, &sa, nullptr) < 0)
    err(1, "sigaction SIGCHLD");
  if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0)
    err(1, "prctl PR_SET_CHILD_SUBREAPER");
  if (fflush(nullptr) == EOF)
    err(1, "fflush");

  pid_t pid = fork();
  if (pid < 0)
    err(1, "fork");
  if (pid == 0)
    child(run, ws, argv, uid, gid);

  // After fork, so the child execs with default dispositions: Ctrl-C kills
  // the agent, and we survive to print the diff.
  sa.sa_handler = SIG_IGN;
  if (sigaction(SIGINT, &sa, nullptr) < 0 ||
      sigaction(SIGQUIT, &sa, nullptr) < 0)
    err(1, "sigaction");

  while (waitpid(pid, &st, 0) < 0)
    if (errno != EINTR)
      err(1, "waitpid %d", pid);
  reap_all();
  return st;
}
