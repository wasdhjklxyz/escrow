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

// Exit codes of a child that never reached the command. 125 is the usual
// "the wrapper failed" code (env, chroot, timeout), 127 is "exec failed".
enum { JAIL_SETUP_FAILED = 125, JAIL_EXEC_FAILED = 127 };

// The agent's pid while it may be signalled (unreaped), else 0.
static volatile sig_atomic_t agent_pid;

// The kernel parses each of these files from a single write().
static int write_file(const char *path, const char *buf) {
  size_t len = strlen(buf);

  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    warn("open %s", path);
    return -1;
  }
  ssize_t n = write(fd, buf, len);
  if (n != (ssize_t)len) {
    n < 0 ? warn("write %s", path) : warnx("write %s: short write", path);
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
    if (errno == EPERM || errno == ENOSPC)
      warnx("hint: check user.max_user_namespaces and, on Ubuntu, "
            "kernel.apparmor_restrict_unprivileged_userns");
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
                               char *const argv[], uid_t uid, gid_t gid,
                               pid_t parent) {
  if (enter_ns(uid, gid) < 0)
    _exit(JAIL_SETUP_FAILED);
  // If escrow dies (even SIGKILL), take the agent down with it. Set after
  // unshare, which changes our creds and so clears the death signal. The
  // getppid check covers a parent that died before the prctl.
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
    warn("prctl PR_SET_PDEATHSIG");
    _exit(JAIL_SETUP_FAILED);
  }
  if (getppid() != parent)
    _exit(JAIL_SETUP_FAILED);
  if (overlay_mount(run, ws) < 0)
    _exit(JAIL_SETUP_FAILED);
  if (chdir(run->merged) < 0) {
    warn("chdir %s", run->merged);
    _exit(JAIL_SETUP_FAILED);
  }
  execvp(argv[0], argv);
  warn("exec %s", argv[0]);
  _exit(JAIL_EXEC_FAILED);
}

// SIGTERM/SIGHUP (timeout, a CI cancel, a closed terminal) kill the agent
// instead of us, so we still reap leftovers, print the diff, and restore
// any modes the walk relaxed. After the agent is reaped they do nothing.
static void kill_agent(int sig) {
  (void)sig;
  if (agent_pid > 0)
    kill(agent_pid, SIGKILL);
}

// We are the agent's subreaper, so anything it left running was
// reparented to us. SIGKILL whatever is listed, reap, repeat until no
// children remain. thread-self lists only this thread's children, which is
// all of them because escrow is single-threaded. Needs
// CONFIG_PROC_CHILDREN (set by NixOS, Fedora, Ubuntu). Without it this
// fails with ENOENT after the agent has run. The list can miss a process
// mid-reparent, so an empty list polls (WNOHANG) rather than blocking on a
// live child we never signalled. A tree that forks faster than we kill can
// keep this looping; M2's pid ns closes that by killing the whole ns.
static void reap_all(void) {
  static const char path[] = "/proc/thread-self/children";

  for (;;) {
    FILE *f = fopen(path, "re");
    if (!f)
      err(1, "open %s", path);
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
  pid_t self = getpid();
  struct sigaction sa = {.sa_handler = SIG_DFL};
  siginfo_t info;
  int status;

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
    child(run, ws, argv, uid, gid, self);
  agent_pid = pid;

  // After fork, so the child execs with default dispositions. Ctrl-C hits
  // the whole foreground group: the agent dies, we survive to print the
  // diff. They stay ignored through the walk on purpose (see diff.c).
  sa.sa_handler = SIG_IGN;
  if (sigaction(SIGINT, &sa, nullptr) < 0)
    err(1, "sigaction SIGINT");
  if (sigaction(SIGQUIT, &sa, nullptr) < 0)
    err(1, "sigaction SIGQUIT");
  sa.sa_handler = kill_agent;
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGTERM, &sa, nullptr) < 0)
    err(1, "sigaction SIGTERM");
  if (sigaction(SIGHUP, &sa, nullptr) < 0)
    err(1, "sigaction SIGHUP");

  // Wait without reaping (WNOWAIT), clear agent_pid, then reap: the pid
  // can't be recycled while kill_agent might still signal it.
  while (waitid(P_PID, pid, &info, WEXITED | WNOWAIT) < 0)
    if (errno != EINTR)
      err(1, "waitid %d", pid);
  agent_pid = 0;
  while (waitpid(pid, &status, 0) < 0)
    if (errno != EINTR)
      err(1, "waitpid %d", pid);
  reap_all();
  return status;
}
