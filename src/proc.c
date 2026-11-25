#include "proc.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static pid_t spawn(char *const argv[], int in_fd, int out_fd) {
  posix_spawn_file_actions_t fa;
  pid_t pid;
  int e;

  if ((e = posix_spawn_file_actions_init(&fa)) != 0)
    (errno = e), err(1, "posix_spawn_file_actions_init");
  if (in_fd >= 0)
    e = posix_spawn_file_actions_adddup2(&fa, in_fd, 0);
  else
    e = posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
  if (e == 0 && out_fd >= 0)
    e = posix_spawn_file_actions_adddup2(&fa, out_fd, 1);
  if (e != 0)
    (errno = e), err(1, "posix_spawn_file_actions");
  // escrow ignores SIGINT/SIGQUIT/SIGPIPE, and ignored dispositions
  // survive exec: give the helper the defaults back.
  posix_spawnattr_t at;
  sigset_t def;
  sigemptyset(&def);
  sigaddset(&def, SIGINT);
  sigaddset(&def, SIGQUIT);
  sigaddset(&def, SIGPIPE);
  if ((e = posix_spawnattr_init(&at)) != 0 ||
      (e = posix_spawnattr_setsigdefault(&at, &def)) != 0 ||
      (e = posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGDEF)) != 0)
    (errno = e), err(1, "posix_spawnattr");
  if ((e = posix_spawnp(&pid, argv[0], &fa, &at, argv, environ)) != 0)
    (errno = e), err(1, "spawn %s", argv[0]);
  posix_spawn_file_actions_destroy(&fa);
  posix_spawnattr_destroy(&at);
  return pid;
}

static int wait_for(pid_t pid, const char *what) {
  int st;

  while (waitpid(pid, &st, 0) < 0)
    if (errno != EINTR)
      err(1, "waitpid %s", what);
  return WIFSIGNALED(st) ? 128 + WTERMSIG(st) : WEXITSTATUS(st);
}

int run_cmd(char *const argv[], int in_fd, int out_fd) {
  return wait_for(spawn(argv, in_fd, out_fd), argv[0]);
}

void sha256_open(struct sha256 *h) {
  static char *const argv[] = {"sha256sum", nullptr};
  int in[2], out[2];

  if (pipe2(in, O_CLOEXEC) < 0 || pipe2(out, O_CLOEXEC) < 0)
    err(1, "pipe2");
  h->pid = spawn(argv, in[0], out[1]);
  close(in[0]);
  close(out[1]);
  h->in = in[1];
  h->out = out[0];
}

int write_all(int fd, const void *buf, size_t n) {
  const char *p = buf;

  while (n > 0) {
    ssize_t w = write(fd, p, n);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    p += w;
    n -= (size_t)w;
  }
  return 0;
}

void sha256_write(struct sha256 *h, const void *buf, size_t n) {
  if (write_all(h->in, buf, n) < 0)
    err(1, "write sha256sum");
}

void sha256_close(struct sha256 *h, char hex[SHA256_HEX + 1]) {
  char buf[SHA256_HEX + 8];
  size_t got = 0;
  ssize_t r;

  if (close(h->in) < 0)
    err(1, "close sha256sum input");
  while (got < sizeof buf && (r = read(h->out, buf + got, sizeof buf - got)))
    if (r < 0) {
      if (errno != EINTR)
        err(1, "read sha256sum");
    } else {
      got += (size_t)r;
    }
  close(h->out);
  if (wait_for(h->pid, "sha256sum") != 0)
    errx(1, "sha256sum failed");
  // "<64 hex>  -\n"
  if (got < SHA256_HEX + 1 || buf[SHA256_HEX] != ' ' ||
      strspn(buf, "0123456789abcdef") != SHA256_HEX)
    errx(1, "sha256sum: unexpected output");
  memcpy(hex, buf, SHA256_HEX);
  hex[SHA256_HEX] = '\0';
}

void sha256_file(const char *path, char hex[SHA256_HEX + 1]) {
  struct sha256 h;
  char buf[1 << 16];
  ssize_t n;

  int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    err(1, "open %s", path);
  sha256_open(&h);
  while ((n = read(fd, buf, sizeof buf)) != 0) {
    if (n < 0) {
      if (errno == EINTR)
        continue;
      err(1, "read %s", path);
    }
    sha256_write(&h, buf, (size_t)n);
  }
  close(fd);
  sha256_close(&h, hex);
}

void sha256_buf(const void *buf, size_t n, char hex[SHA256_HEX + 1]) {
  struct sha256 h;

  sha256_open(&h);
  sha256_write(&h, buf, n);
  sha256_close(&h, hex);
}
