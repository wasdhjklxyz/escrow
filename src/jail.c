#include "jail.h"

#include "landlock.h"
#include "overlay.h"
#include "policy.h"
#include "seccomp.h"

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

// Where init keeps the log fd across close_range, for the agent's 1 and 2.
enum { LOG_FD = 3 };

// The process kill_target SIGKILLs while it is unreaped, else 0. In escrow
// that is init; inside init (a separate copy) it is the agent.
static volatile sig_atomic_t target_pid;

// Signals that kill the agent instead of us (escrow: SIGTERM/SIGHUP;
// init: all four).
static const int forwarded[] = {SIGINT, SIGQUIT, SIGTERM, SIGHUP};

extern char **environ;

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
  if (write_file("/proc/sys/user/max_user_namespaces", "0") < 0)
    return -1;
  if (sethostname("escrow", strlen("escrow")) < 0) {
    warn("sethostname");
    return -1;
  }
  return 0;
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
    warn("move_mount %s /%s", type, path);
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
static int bind_mount(int root, const char *src, const char *dst,
                      unsigned attrs) {
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
  // The mountpoint: a dir, or an empty file (mknod of S_IFREG needs no
  // caps).
  if ((S_ISDIR(st.st_mode) ? mkdirat(root, dst, 0755)
                           : mknodat(root, dst, S_IFREG | 0444, 0)) < 0) {
    warn("mountpoint /%s", dst);
    goto out;
  }
  if (mount_setattr(fd, "", AT_EMPTY_PATH, &ma, sizeof ma) < 0) {
    warn("mount_setattr %s", src);
    goto out;
  }
  if ((r = move_mount(fd, "", root, dst, MOVE_MOUNT_F_EMPTY_PATH)) < 0)
    warn("move_mount /%s", dst);
out:
  close(fd);
  return r;
}

// /bin/sh -> env/bin/sh (and /usr/bin/env), only if the role has it.
// system(3), popen(3) and most interpreters hardcode these paths.
static int shim(int root, const char *env, const char *name,
                const char *linkpath) {
  char target[PATH_MAX];

  int n = snprintf(target, sizeof target, "%s/bin/%s", env, name);
  if (n < 0 || n >= (int)sizeof target) {
    warnx("path too long: %s/bin/%s", env, name);
    return -1;
  }
  if (access(target, X_OK) < 0) {
    warnx("role has no %s: /%s will be missing", name, linkpath);
    return 0;
  }
  if (symlinkat(target, root, linkpath) < 0) {
    warn("symlink /%s", linkpath);
    return -1;
  }
  return 0;
}

static int build_devs(int root) {
  static const char *const nodes[] = {"/dev/null", "/dev/zero", "/dev/full",
                                      "/dev/random", "/dev/urandom"};
  static const char *const links[][2] = {{"/proc/self/fd", "dev/fd"},
                                         {"/proc/self/fd/0", "dev/stdin"},
                                         {"/proc/self/fd/1", "dev/stdout"},
                                         {"/proc/self/fd/2", "dev/stderr"}};

  for (size_t i = 0; i < sizeof nodes / sizeof *nodes; i++)
    if (bind_mount(root, nodes[i], nodes[i] + 1,
                   MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC) < 0)
      return -1;
  for (size_t i = 0; i < sizeof links / sizeof *links; i++) {
    if (symlinkat(links[i][0], root, links[i][1]) < 0) {
      warn("symlink /%s", links[i][1]);
      return -1;
    }
  }
  return 0;
}

// Under --net: the host's resolver config, read-only, so names resolve.
static int bind_resolv(int root) {
  char real[PATH_MAX];

  // Often a symlink (systemd-resolved, NixOS /etc/static): bind its target.
  if (!realpath("/etc/resolv.conf", real)) {
    warn("realpath /etc/resolv.conf");
    return -1;
  }
  if (mkdirat(root, "etc", 0755) < 0) {
    warn("mkdir /etc");
    return -1;
  }
  return bind_mount(root, real, "etc/resolv.conf",
                    MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
                        MOUNT_ATTR_NOEXEC);
}

// Init only. Builds the jail's root on a tmpfs at run->root and pivots
// into it. Afterwards the host fs is unreachable by path: the old root is
// detached and close_range already dropped every inherited fd but 0-2 and
// the log (those never reach the agent, see agent()).
static int build_root(const struct jail *j) {
  static const char *const dirs[] = {"nix", "nix/store", "work",
                                     "tmp", "dev",       "proc",
                                     "bin", "usr",       "usr/bin"};
  const struct policy *p = j->policy;
  const unsigned nosuid_nodev = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;
  const unsigned noexec = nosuid_nodev | MOUNT_ATTR_NOEXEC;
  struct mount_attr ro = {.attr_set = MOUNT_ATTR_RDONLY};
  int r = -1, fd;

  int root = mount_fs("tmpfs", "0755", AT_FDCWD, j->run->root, nosuid_nodev);
  if (root < 0)
    return -1;
  for (size_t i = 0; i < sizeof dirs / sizeof *dirs; i++) {
    if (mkdirat(root, dirs[i], 0755) < 0) {
      warn("mkdir /%s", dirs[i]);
      goto out;
    }
  }
  for (size_t i = 0; i < p->nstore; i++) {
    const char *rel = p->store[i] + 1; // the same path under the new root
    if (bind_mount(root, p->store[i], rel, MOUNT_ATTR_RDONLY | nosuid_nodev) <
        0)
      goto out;
  }
  // Before pivot: fsconfig resolves the lower/upper paths in the host fs.
  if (overlay_mount(j->run, j->ws, root, "work") < 0)
    goto out;
  if ((fd = mount_fs("tmpfs", nullptr, root, "tmp", noexec)) < 0)
    goto out;
  close(fd);
  // nodev would make the bound device nodes below unusable.
  if ((fd = mount_fs("tmpfs", "0755", root, "dev",
                     MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC)) < 0)
    goto out;
  close(fd);
  if (build_devs(root) < 0)
    goto out;
  // proc shows the pid ns of the process that mounts it: ours, as PID 1.
  if ((fd = mount_fs("proc", nullptr, root, "proc", noexec)) < 0)
    goto out;
  close(fd);
  if (j->net && bind_resolv(root) < 0)
    goto out;
  if (shim(root, p->env, "sh", "bin/sh") < 0 ||
      shim(root, p->env, "env", "usr/bin/env") < 0)
    goto out;

  // pivot_root(".", "."): the old root ends up stacked on top of the new
  // one at "/", and the detach takes it away, leaving cwd at the new root.
  if (fchdir(root) < 0) {
    warn("fchdir %s", j->run->root);
    goto out;
  }
  if (syscall(SYS_pivot_root, ".", ".") < 0) {
    warn("pivot_root");
    goto out;
  }
  if (umount2(".", MNT_DETACH) < 0) {
    warn("umount2 old root");
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

// The first NAME=value in environ, or nullptr (getenv, but the whole entry).
static char *env_entry(const char *name) {
  size_t n = strlen(name);
  for (char **e = environ; e && *e; e++)
    if (strncmp(*e, name, n) == 0 && (*e)[n] == '=')
      return *e;
  return nullptr;
}

// Clean env: PATH (the role's env/bin), HOME=/tmp, PWD=/work,
// SSL_CERT_FILE if the role ships cacert, TERM and LANG, and the --env
// names the operator chose. Nothing else from the host, so its tokens
// (GITHUB_TOKEN, AWS_*, SSH_AUTH_SOCK) stay out. execvp searches the PATH
// of environ, so environ itself is swapped.
static int clean_environ(const char *env, char *const pass[]) {
  static const char *const keep[] = {"TERM", "LANG"};
  static char path[PATH_MAX], certs[PATH_MAX];
  size_t npass = 0, n = 0;

  while (pass && pass[npass])
    npass++;
  // PATH, HOME, PWD, SSL_CERT_FILE, the kept ones, --env ones, nullptr.
  char **envp =
      calloc(4 + sizeof keep / sizeof *keep + npass + 1, sizeof *envp);
  if (!envp) {
    warn("calloc");
    return -1;
  }
  int len = snprintf(path, sizeof path, "PATH=%s/bin", env);
  if (len < 0 || len >= (int)sizeof path) {
    warnx("path too long: %s/bin", env);
    return -1;
  }
  envp[n++] = path;
  envp[n++] = "HOME=/tmp";
  envp[n++] = "PWD=/work";
  // A role that ships CA certificates (nixpkgs cacert) gets them used:
  // the jail has no /etc/ssl.
  len = snprintf(certs, sizeof certs,
                 "SSL_CERT_FILE=%s/etc/ssl/certs/ca-bundle.crt", env);
  if (len > 0 && len < (int)sizeof certs &&
      access(certs + strlen("SSL_CERT_FILE="), R_OK) == 0)
    envp[n++] = certs;
  for (size_t i = 0; i < sizeof keep / sizeof *keep; i++)
    if (env_entry(keep[i]))
      envp[n++] = env_entry(keep[i]);
  // --env NAME: the operator chose to hand this one to the agent.
  for (size_t i = 0; i < npass; i++)
    if (env_entry(pass[i]))
      envp[n++] = env_entry(pass[i]);
  environ = envp;
  return 0;
}

// The agent's fds: stdin from /dev/null (an inherited tty would let it read
// what the user types, and a dir fd would reach the host fs), stdout and
// stderr to the run log (on escrow's stdout it could forge or hide diff
// lines). LOG_FD itself is closed.
static int redirect_stdio(void) {
  int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
  if (null < 0) {
    warn("open /dev/null");
    return -1;
  }
  if (dup2(null, 0) < 0 || dup2(LOG_FD, 1) < 0 || dup2(LOG_FD, 2) < 0) {
    warn("dup2");
    return -1;
  }
  close(null);
  close(LOG_FD);
  return 0;
}

static void kill_target(int sig) {
  (void)sig;
  if (target_pid > 0)
    kill(target_pid, SIGKILL);
}

[[noreturn]] static void agent(const struct jail *j, char *const argv[],
                               const sigset_t *mask) {
  struct sigaction dfl = {.sa_handler = SIG_DFL};

  for (size_t i = 0; i < sizeof forwarded / sizeof *forwarded; i++) {
    if (sigaction(forwarded[i], &dfl, nullptr) < 0) {
      warn("sigaction SIG%s", sigabbrev_np(forwarded[i]));
      _exit(JAIL_SETUP_FAILED);
    }
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
  if (clean_environ(j->policy->env, j->pass_env) < 0)
    _exit(JAIL_SETUP_FAILED);
  // Landlock and seccomp require it, and it keeps exec from ever gaining
  // privileges.
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    warn("prctl PR_SET_NO_NEW_PRIVS");
    _exit(JAIL_SETUP_FAILED);
  }
  if (landlock_apply(j->landlock_abi, j->net, LOG_FD) < 0 ||
      seccomp_apply() < 0)
    _exit(JAIL_SETUP_FAILED);
  // Last: errors before this point still reach the operator's terminal.
  if (redirect_stdio() < 0)
    _exit(JAIL_SETUP_FAILED);
  execvp(argv[0], argv);
  warn("exec %s", argv[0]);
  _exit(JAIL_EXEC_FAILED);
}

// PID 1 of the new pid ns, in the new user+mount(+net) ns, running our own
// code (no exec). Never returns: exits with the agent's status. Its exit
// kills everything else in the pid ns.
[[noreturn]] static void init(const struct jail *j, char *const argv[],
                              uid_t uid, gid_t gid, int parent_pidfd, int log) {
  struct sigaction sa = {.sa_handler = kill_target, .sa_flags = SA_RESTART};
  struct pollfd pfd = {.fd = parent_pidfd, .events = POLLIN};
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
  // Any other inherited fd, a dir fd above all, would reach the host fs
  // after pivot_root. Keep only stdio (init's own messages) and the log.
  if (dup2(log, LOG_FD) < 0) {
    warn("dup2 log");
    _exit(JAIL_SETUP_FAILED);
  }
  if (close_range(LOG_FD + 1, ~0U, 0) < 0) {
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
  for (size_t i = 0; i < sizeof forwarded / sizeof *forwarded; i++) {
    if (sigaction(forwarded[i], &sa, nullptr) < 0) {
      warn("sigaction SIG%s", sigabbrev_np(forwarded[i]));
      _exit(JAIL_SETUP_FAILED);
    }
  }
  pid_t pid = fork();
  if (pid < 0) {
    warn("fork");
    _exit(JAIL_SETUP_FAILED);
  }
  if (pid == 0)
    agent(j, argv, &old);
  target_pid = pid;
  if (sigprocmask(SIG_SETMASK, &old, nullptr) < 0) {
    warn("sigprocmask");
    kill(pid, SIGKILL);
    _exit(JAIL_SETUP_FAILED);
  }

  // Orphans reparent to us: reap them until the agent itself exits.
  for (;;) {
    pid_t reaped = waitpid(-1, &status, 0);
    if (reaped < 0) {
      if (errno == EINTR)
        continue;
      warn("waitpid");
      _exit(JAIL_SETUP_FAILED);
    }
    if (reaped == pid)
      break;
  }
  // PID 1 can't die of a signal sent from inside its own ns, so a killed
  // agent is reported the way a shell would: 128+N.
  _exit(WIFSIGNALED(status) ? 128 + WTERMSIG(status) : WEXITSTATUS(status));
}

int jail_run(const struct jail *j, char *const argv[]) {
  // The maps must name our ids as the host sees them.
  uid_t uid = getuid();
  gid_t gid = getgid();
  struct sigaction sa = {.sa_handler = SIG_DFL};
  struct clone_args ca = {
      // IPC: else the agent reads and writes the user's SysV shm and
      // mqueues. UTS, cgroup: else it sees the host's name and cgroup path.
      .flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC |
               CLONE_NEWUTS | CLONE_NEWCGROUP | (j->net ? 0 : CLONE_NEWNET),
      .exit_signal = SIGCHLD,
  };
  siginfo_t info;
  int status;

  // An inherited SIG_IGN for SIGCHLD makes the kernel auto-reap children,
  // and waitpid would fail with ECHILD.
  if (sigaction(SIGCHLD, &sa, nullptr) < 0)
    err(1, "sigaction SIGCHLD");
  int log = open(
      j->run->log,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_APPEND | O_CLOEXEC, 0600);
  if (log < 0)
    err(1, "open %s", j->run->log);
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
    init(j, argv, uid, gid, self, log);
  target_pid = pid;
  if (close(self) < 0 || close(log) < 0)
    err(1, "close");

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
  sa.sa_handler = kill_target;
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGTERM, &sa, nullptr) < 0)
    err(1, "sigaction SIGTERM");
  if (sigaction(SIGHUP, &sa, nullptr) < 0)
    err(1, "sigaction SIGHUP");

  // Wait without reaping (WNOWAIT), clear target_pid, then reap: the pid
  // can't be recycled while kill_target might still signal it. Nothing
  // else can become our child: orphans in the jail reparent to init, never
  // across the pid ns boundary.
  while (waitid(P_PID, pid, &info, WEXITED | WNOWAIT) < 0)
    if (errno != EINTR)
      err(1, "waitid %d", pid);
  target_pid = 0;
  while (waitpid(pid, &status, 0) < 0)
    if (errno != EINTR)
      err(1, "waitpid %d", pid);
  return status;
}
