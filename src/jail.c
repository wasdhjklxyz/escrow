#include "jail.h"

#include "landlock.h"
#include "overlay.h"
#include "policy.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/sched.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/pidfd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

// Exit codes of an init that never ran the command. 125 is the usual
// "the wrapper failed" code (env, chroot, timeout), 127 is "exec failed".
enum { JAIL_SETUP_FAILED = 125, JAIL_EXEC_FAILED = 127 };

// The one process kill_agent may SIGKILL while it is unreaped, else 0. In
// escrow that is init; inside init (a separate copy) it is the agent.
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

// Init only, still seeing the host fs. Maps our own uid/gid to themselves:
// init keeps the full caps clone3 gave it in the new user ns, and the
// agent, a non-root uid, loses them all at execve.
static int setup_ns(uid_t uid, gid_t gid) {
  char map[64];

  // setgroups must be denied before an unprivileged gid_map write.
  if (write_file("/proc/self/setgroups", "deny") < 0)
    return -1;
  snprintf(map, sizeof map, "%u %u 1\n", gid, gid);
  if (write_file("/proc/self/gid_map", map) < 0)
    return -1;
  snprintf(map, sizeof map, "%u %u 1\n", uid, uid);
  if (write_file("/proc/self/uid_map", map) < 0)
    return -1;
  // Before any other mount: stop host mount events propagating in.
  if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) {
    warn("mount / private");
    return -1;
  }
  // Per user ns: no user ns may be created below ours, so the agent can't
  // get a fresh set of caps with `unshare -r`. Needs CAP_SYS_RESOURCE here,
  // which init has and the agent won't.
  return write_file("/proc/sys/user/max_user_namespaces", "0");
}

// A new fs of `type` attached at dirfd/path. Returns the mount fd (the new
// fs's root, usable as a dirfd) or -1.
static int mount_fs(const char *type, const char *mode, int dirfd,
                    const char *path, unsigned attrs) {
  int mfd = -1;
  int fsfd = fsopen(type, FSOPEN_CLOEXEC);
  if (fsfd < 0) {
    warn("fsopen %s", type);
    return -1;
  }
  if (mode && fsconfig(fsfd, FSCONFIG_SET_STRING, "mode", mode, 0) < 0) {
    warn("fsconfig %s mode", type);
    goto out;
  }
  if (fsconfig(fsfd, FSCONFIG_CMD_CREATE, nullptr, nullptr, 0) < 0) {
    warn("fsconfig %s create", type);
    goto out;
  }
  if ((mfd = fsmount(fsfd, FSMOUNT_CLOEXEC, attrs)) < 0) {
    warn("fsmount %s", type);
    goto out;
  }
  if (move_mount(mfd, "", dirfd, path, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
    warn("move_mount %s %s", type, path);
    close(mfd);
    mfd = -1;
  }
out:
  close(fsfd);
  return mfd;
}

// Bind src (a dir or regular file) at root/dst with attrs set on the bind.
// open_tree + mount_setattr only ever adds flags, so it never trips over
// the flags the kernel locked on mounts inherited from the host.
static int bind(int root, const char *src, const char *dst, unsigned attrs) {
  struct mount_attr ma = {.attr_set = attrs};
  struct stat st;
  int r = -1;

  int fd = open_tree(AT_FDCWD, src,
                     OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_SYMLINK_NOFOLLOW);
  if (fd < 0) {
    warn("open_tree %s", src);
    return -1;
  }
  if (fstat(fd, &st) < 0) {
    warn("fstat %s", src);
    goto out;
  }
  if (S_ISDIR(st.st_mode)) {
    if (mkdirat(root, dst, 0755) < 0) {
      warn("mkdir /%s", dst);
      goto out;
    }
  } else {
    int t = openat(root, dst, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0444);
    if (t < 0) {
      warn("create /%s", dst);
      goto out;
    }
    close(t);
  }
  if (mount_setattr(fd, "", AT_EMPTY_PATH, &ma, sizeof ma) < 0) {
    warn("mount_setattr %s", src);
    goto out;
  }
  if ((r = move_mount(fd, "", root, dst, MOVE_MOUNT_F_EMPTY_PATH)) < 0)
    warn("move_mount %s", src);
out:
  close(fd);
  return r;
}

static int mkdirs(int root, const char *const dirs[], size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (mkdirat(root, dirs[i], 0755) < 0 && errno != EEXIST) {
      warn("mkdir /%s", dirs[i]);
      return -1;
    }
  }
  return 0;
}

// /bin/sh -> env/bin/sh (and /usr/bin/env), only if the role has it.
// system(3), popen(3) and most interpreters hardcode these paths.
static int shim(int root, const char *env, const char *name, const char *link) {
  char target[PATH_MAX];

  int n = snprintf(target, sizeof target, "%s/bin/%s", env, name);
  if (n < 0 || n >= (int)sizeof target) {
    warnx("path too long: %s/bin/%s", env, name);
    return -1;
  }
  if (access(target, X_OK) < 0)
    return 0;
  if (symlinkat(target, root, link) < 0) {
    warn("symlink /%s", link);
    return -1;
  }
  return 0;
}

static int build_devs(int root) {
  static const char *const nodes[] = {"null", "zero", "full", "random",
                                      "urandom"};
  static const char *const links[][2] = {{"/proc/self/fd", "dev/fd"},
                                         {"/proc/self/fd/0", "dev/stdin"},
                                         {"/proc/self/fd/1", "dev/stdout"},
                                         {"/proc/self/fd/2", "dev/stderr"}};
  char src[32], dst[32];

  for (size_t i = 0; i < sizeof nodes / sizeof *nodes; i++) {
    snprintf(src, sizeof src, "/dev/%s", nodes[i]);
    snprintf(dst, sizeof dst, "dev/%s", nodes[i]);
    if (bind(root, src, dst, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC) < 0)
      return -1;
  }
  for (size_t i = 0; i < sizeof links / sizeof *links; i++) {
    if (symlinkat(links[i][0], root, links[i][1]) < 0) {
      warn("symlink /%s", links[i][1]);
      return -1;
    }
  }
  return 0;
}

// Init only. Builds the jail's root on a tmpfs at run->root and pivots
// into it. Afterwards the host fs is unreachable: the old root is detached
// and close_range already dropped every inherited fd.
static int build_root(const struct jail *j) {
  static const char *const dirs[] = {"nix", "nix/store", "work",
                                     "tmp", "dev",       "proc",
                                     "bin", "usr",       "usr/bin"};
  const struct policy *p = j->policy;
  const unsigned nosuid = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;
  struct mount_attr ro = {.attr_set = MOUNT_ATTR_RDONLY};
  int r = -1, fd;

  int root = mount_fs("tmpfs", "0755", AT_FDCWD, j->run->root, nosuid);
  if (root < 0)
    return -1;
  if (mkdirs(root, dirs, sizeof dirs / sizeof *dirs) < 0)
    goto out;
  for (size_t i = 0; i < p->n; i++)
    if (bind(root, p->store[i], p->store[i] + 1, MOUNT_ATTR_RDONLY | nosuid) <
        0)
      goto out;
  // Before pivot: fsconfig resolves the lower/upper paths in the host fs.
  if (overlay_mount(j->run, j->ws, root, "work") < 0)
    goto out;
  if ((fd = mount_fs("tmpfs", nullptr, root, "tmp", nosuid)) < 0)
    goto out;
  close(fd);
  if ((fd = mount_fs("tmpfs", "0755", root, "dev",
                     MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC)) < 0)
    goto out;
  close(fd);
  if (build_devs(root) < 0)
    goto out;
  // proc shows the pid ns of the process that mounts it: ours, as PID 1.
  if ((fd = mount_fs("proc", nullptr, root, "proc",
                     nosuid | MOUNT_ATTR_NOEXEC)) < 0)
    goto out;
  close(fd);
  if (shim(root, p->env, "sh", "bin/sh") < 0 ||
      shim(root, p->env, "env", "usr/bin/env") < 0)
    goto out;

  // pivot_root(".", "."): the old root ends up stacked on top of the new
  // one at "/", and the detach takes it away. No put_old dir needed.
  if (fchdir(root) < 0) {
    warn("fchdir %s", j->run->root);
    goto out;
  }
  if (syscall(SYS_pivot_root, ".", ".") < 0) {
    warn("pivot_root");
    goto out;
  }
  if (umount2(".", MNT_DETACH) < 0) {
    warn("umount old root");
    goto out;
  }
  if (chdir("/") < 0) {
    warn("chdir /");
    goto out;
  }
  // The agent owns these tmpfs roots (same uid). Freeze them now that they
  // are built. Not recursive: the binds below keep their own flags.
  if (mount_setattr(AT_FDCWD, "/", 0, &ro, sizeof ro) < 0 ||
      mount_setattr(AT_FDCWD, "/dev", 0, &ro, sizeof ro) < 0) {
    warn("mount_setattr ro");
    goto out;
  }
  r = 0;
out:
  close(root);
  return r;
}

// Clean env: nothing from the host but TERM and LANG, so host tokens
// (GITHUB_TOKEN, AWS_*, SSH_AUTH_SOCK) don't reach the agent.
static int set_env(const char *env) {
  static const char *const keep[] = {"TERM", "LANG"};
  char *saved[sizeof keep / sizeof *keep] = {};
  char path[PATH_MAX];
  int r = -1;

  int n = snprintf(path, sizeof path, "%s/bin", env);
  if (n < 0 || n >= (int)sizeof path) {
    warnx("path too long: %s/bin", env);
    return -1;
  }
  for (size_t i = 0; i < sizeof keep / sizeof *keep; i++) {
    const char *v = getenv(keep[i]);
    if (v && !(saved[i] = strdup(v))) {
      warn("strdup");
      goto out;
    }
  }
  if (clearenv() != 0) {
    warnx("clearenv failed");
    goto out;
  }
  if (setenv("PATH", path, 1) < 0 || setenv("HOME", "/tmp", 1) < 0 ||
      setenv("PWD", "/work", 1) < 0) {
    warn("setenv");
    goto out;
  }
  for (size_t i = 0; i < sizeof keep / sizeof *keep; i++) {
    if (saved[i] && setenv(keep[i], saved[i], 1) < 0) {
      warn("setenv %s", keep[i]);
      goto out;
    }
  }
  r = 0;
out:
  for (size_t i = 0; i < sizeof keep / sizeof *keep; i++)
    free(saved[i]);
  return r;
}

// SIGTERM/SIGHUP (timeout, a CI cancel, a closed terminal) and, in init,
// SIGINT/SIGQUIT kill the agent instead of us, so the diff still gets
// printed. After the agent is reaped they do nothing.
static void kill_agent(int sig) {
  (void)sig;
  if (agent_pid > 0)
    kill(agent_pid, SIGKILL);
}

static const int forwarded[] = {SIGINT, SIGQUIT, SIGTERM, SIGHUP};

[[noreturn]] static void agent(const struct jail *j, char *const argv[],
                               const sigset_t *mask) {
  struct sigaction dfl = {.sa_handler = SIG_DFL};

  for (size_t i = 0; i < sizeof forwarded / sizeof *forwarded; i++)
    if (sigaction(forwarded[i], &dfl, nullptr) < 0) {
      warn("sigaction");
      _exit(JAIL_SETUP_FAILED);
    }
  if (sigprocmask(SIG_SETMASK, mask, nullptr) < 0) {
    warn("sigprocmask");
    _exit(JAIL_SETUP_FAILED);
  }
  // No controlling tty: TIOCSTI can't push keystrokes into the host
  // terminal through an inherited tty fd.
  if (setsid() < 0) {
    warn("setsid");
    _exit(JAIL_SETUP_FAILED);
  }
  if (chdir("/work") < 0) {
    warn("chdir /work");
    _exit(JAIL_SETUP_FAILED);
  }
  if (set_env(j->policy->env) < 0)
    _exit(JAIL_SETUP_FAILED);
  // Landlock requires it, and it keeps exec from ever gaining privileges.
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    warn("prctl PR_SET_NO_NEW_PRIVS");
    _exit(JAIL_SETUP_FAILED);
  }
  if (landlock_apply(j->abi, j->net) < 0)
    _exit(JAIL_SETUP_FAILED);
  execvp(argv[0], argv);
  warn("exec %s", argv[0]);
  _exit(JAIL_EXEC_FAILED);
}

// PID 1 of the new pid ns, in the new user+mount(+net) ns, running our own
// code (no exec). Never returns: exits with the agent's status. Its exit
// kills everything else in the pid ns.
[[noreturn]] static void init(const struct jail *j, char *const argv[],
                              uid_t uid, gid_t gid, int parent) {
  struct sigaction sa = {.sa_handler = kill_agent, .sa_flags = SA_RESTART};
  struct pollfd pfd = {.fd = parent, .events = POLLIN};
  sigset_t all, old;
  int status;

  // If escrow dies (even SIGKILL), take the jail down with it. getppid()
  // is 0 here (the parent is outside our pid ns), so check escrow's pidfd
  // instead: readable once escrow has exited, covering a death before the
  // prctl.
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
    warn("prctl PR_SET_PDEATHSIG");
    _exit(JAIL_SETUP_FAILED);
  }
  int ready = poll(&pfd, 1, 0);
  if (ready != 0) {
    if (ready < 0)
      warn("poll pidfd");
    _exit(JAIL_SETUP_FAILED);
  }
  // Any inherited fd, a dir fd above all, would reach the host fs after
  // pivot_root. This also closes the pidfd.
  if (close_range(3, ~0U, 0) < 0) {
    warn("close_range");
    _exit(JAIL_SETUP_FAILED);
  }
  if (setup_ns(uid, gid) < 0 || build_root(j) < 0)
    _exit(JAIL_SETUP_FAILED);

  // Handlers go in with everything blocked, and the agent resets them
  // before unblocking: a signal between fork and exec can't run init's
  // handler in the agent.
  sigfillset(&all);
  if (sigprocmask(SIG_BLOCK, &all, &old) < 0) {
    warn("sigprocmask");
    _exit(JAIL_SETUP_FAILED);
  }
  // PID 1 only gets signals it has a handler for, even from escrow's ns.
  for (size_t i = 0; i < sizeof forwarded / sizeof *forwarded; i++)
    if (sigaction(forwarded[i], &sa, nullptr) < 0) {
      warn("sigaction");
      _exit(JAIL_SETUP_FAILED);
    }
  pid_t pid = fork();
  if (pid < 0) {
    warn("fork");
    _exit(JAIL_SETUP_FAILED);
  }
  if (pid == 0)
    agent(j, argv, &old);
  agent_pid = pid;
  if (sigprocmask(SIG_SETMASK, &old, nullptr) < 0) {
    warn("sigprocmask");
    kill(pid, SIGKILL);
    _exit(JAIL_SETUP_FAILED);
  }

  // Orphans reparent to us: reap them until the agent itself exits.
  for (;;) {
    pid_t p = waitpid(-1, &status, 0);
    if (p < 0) {
      if (errno == EINTR)
        continue;
      warn("waitpid");
      _exit(JAIL_SETUP_FAILED);
    }
    if (p == pid)
      break;
  }
  // PID 1 can't die of a signal sent from inside its own ns, so a killed
  // agent is reported the way a shell would: 128+N.
  _exit(WIFSIGNALED(status) ? 128 + WTERMSIG(status) : WEXITSTATUS(status));
}

// We are init's subreaper. With the pid ns nothing else should ever be
// reparented to us, but SIGKILL whatever is listed, reap, repeat until no
// children remain. thread-self lists only this thread's children, which
// is all of them because escrow is single-threaded. Needs
// CONFIG_PROC_CHILDREN (set by NixOS, Fedora, Ubuntu). An empty list polls
// (WNOHANG) rather than blocking on a live child we never signalled.
static int children(bool kill_them) {
  static const char path[] = "/proc/thread-self/children";
  int pid, n = 0;

  FILE *f = fopen(path, "re");
  if (!f)
    err(1, "open %s", path);
  while (fscanf(f, "%d", &pid) == 1) {
    // Our unreaped child: the pid can't have been recycled.
    if (kill_them && kill(pid, SIGKILL) < 0 && errno != ESRCH)
      err(1, "kill %d", pid);
    n++;
  }
  if (ferror(f))
    err(1, "read %s", path);
  if (fclose(f) == EOF)
    err(1, "close %s", path);
  return n;
}

static void reap_all(void) {
  for (;;) {
    int n = children(true);
    if (waitpid(-1, nullptr, n ? 0 : WNOHANG) < 0) {
      if (errno == ECHILD)
        return;
      if (errno != EINTR)
        err(1, "waitpid");
    }
  }
}

int jail_run(const struct jail *j, char *const argv[]) {
  // The maps must name our ids as the host sees them.
  uid_t uid = getuid();
  gid_t gid = getgid();
  struct sigaction sa = {.sa_handler = SIG_DFL};
  struct clone_args ca = {
      .flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
               (j->net ? 0 : CLONE_NEWNET),
      .exit_signal = SIGCHLD,
  };
  siginfo_t info;
  int status;

  // An inherited SIG_IGN for SIGCHLD makes the kernel auto-reap children,
  // and waitpid would fail with ECHILD.
  if (sigaction(SIGCHLD, &sa, nullptr) < 0)
    err(1, "sigaction SIGCHLD");
  // reap_all kills every child we have. Children inherited from whatever
  // exec'd us (`sh -c 'job & exec escrow ...'`) aren't the agent's.
  if (children(false) > 0)
    errx(1, "already have child processes (inherited across exec); "
            "run escrow without background jobs in the same process");
  if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0)
    err(1, "prctl PR_SET_CHILD_SUBREAPER");
  int self = pidfd_open(getpid(), 0);
  if (self < 0)
    err(1, "pidfd_open");
  if (fflush(nullptr) == EOF)
    err(1, "fflush");

  // Raw clone3 with no stack behaves like fork, but the child is born in
  // the new namespaces while we stay in ours. glibc doesn't know about the
  // child: its cached TID is stale there, so init never calls raise() or
  // abort() (nor any pthread function).
  pid_t pid = (pid_t)syscall(SYS_clone3, &ca, sizeof ca);
  if (pid < 0) {
    warn("clone3");
    if (errno == EPERM || errno == ENOSPC)
      warnx("hint: check user.max_user_namespaces and, on Ubuntu, "
            "kernel.apparmor_restrict_unprivileged_userns");
    exit(1);
  }
  if (pid == 0)
    init(j, argv, uid, gid, self);
  agent_pid = pid;
  if (close(self) < 0)
    err(1, "close pidfd");

  // After clone, so init starts with default dispositions. Ctrl-C hits the
  // whole foreground group: init kills the agent, we survive to print the
  // diff. They stay ignored through the walk on purpose (see diff.c).
  sa.sa_handler = SIG_IGN;
  if (sigaction(SIGINT, &sa, nullptr) < 0)
    err(1, "sigaction SIGINT");
  if (sigaction(SIGQUIT, &sa, nullptr) < 0)
    err(1, "sigaction SIGQUIT");
  // `escrow | head` must not kill us mid-walk with modes relaxed: a closed
  // stdout becomes EPIPE, then err(), then the atexit restore.
  if (sigaction(SIGPIPE, &sa, nullptr) < 0)
    err(1, "sigaction SIGPIPE");
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
