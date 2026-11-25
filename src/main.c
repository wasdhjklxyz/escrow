#include "diff.h"
#include "jail.h"
#include "landlock.h"
#include "overlay.h"
#include "policy.h"

#include <err.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

[[noreturn]] static void usage(void) {
  fprintf(
      stderr,
      "usage: escrow --role POLICY [--net] [--workspace DIR] [--state DIR]"
      " -- <cmd> [args...]\n"
      "  --role POLICY    role policy file (nix build .#role-<name>)\n"
      "  --net            share the host network (TCP connect to 443 only)\n"
      "  --workspace DIR  directory the command sees as /work (default: .)\n"
      "  --state DIR      where runs are kept (default: $ESCROW_STATE)\n"
      "exit: the command's status (128+N if killed by signal N),\n"
      "      125 setup failed, 127 exec failed, 1 escrow error, 2 usage\n");
  exit(2);
}

int main(int argc, char *argv[]) {
  static const struct option opts[] = {
      {"role", required_argument, nullptr, 'r'},
      {"net", no_argument, nullptr, 'n'},
      {"workspace", required_argument, nullptr, 'w'},
      {"state", required_argument, nullptr, 's'},
      {},
  };
  const char *ws = ".";
  const char *state = getenv("ESCROW_STATE");
  const char *role = nullptr;
  char wsreal[PATH_MAX];
  struct policy policy;
  struct run run;
  struct jail j = {.run = &run, .ws = wsreal, .policy = &policy};
  int c;

  // '+': stop at the first non-option, so the command's own flags are
  // never parsed as ours.
  while ((c = getopt_long(argc, argv, "+", opts, nullptr)) != -1) {
    switch (c) {
    case 'r':
      role = optarg;
      break;
    case 'n':
      j.net = true;
      break;
    case 'w':
      ws = optarg;
      break;
    case 's':
      state = optarg;
      break;
    default:
      usage();
    }
  }
  if (optind >= argc || !role)
    usage();
  if (!state || !*state)
    errx(2, "no state dir: pass --state DIR or set ESCROW_STATE");
  // The jail maps our uid to itself. For uid 0 the agent would exec as
  // root in its ns and keep every cap.
  if (getuid() == 0 || geteuid() == 0)
    errx(1, "refusing to run as root");
  // Fail closed: under --net only Landlock keeps the agent off localhost
  // ports and the host's abstract unix sockets (dbus, X11).
  j.abi = landlock_abi();
  if (j.net && j.abi < 6)
    errx(1, "--net needs Landlock ABI >= 6 (kernel >= 6.12), have %d", j.abi);
  if (!realpath(ws, wsreal))
    err(1, "realpath %s", ws);
  policy_load(&policy, role);

  overlay_prepare(&run, state, wsreal);
  warnx("run dir: %s", run.dir);
  int status = jail_run(&j, &argv[optind]);
  if (!diff_print(&run, wsreal))
    warnx("some entries could not be compared (marked ?)");

  if (WIFSIGNALED(status))
    return 128 + WTERMSIG(status);
  return WEXITSTATUS(status);
}
