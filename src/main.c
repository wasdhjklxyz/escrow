#include "diff.h"
#include "jail.h"
#include "overlay.h"

#include <err.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

[[noreturn]] static void usage(void) {
  fprintf(stderr,
          "usage: escrow [--workspace DIR] [--state DIR] -- <cmd> [args...]\n"
          "  --workspace DIR  directory the command sees (default: .)\n"
          "  --state DIR      where runs are kept (default: $ESCROW_STATE)\n"
          "exit: the command's status (128+N if killed by signal N),\n"
          "      125 setup failed, 127 exec failed, 1 escrow error, 2 usage\n");
  exit(2);
}

int main(int argc, char *argv[]) {
  static const struct option opts[] = {
      {"workspace", required_argument, nullptr, 'w'},
      {"state", required_argument, nullptr, 's'},
      {},
  };
  const char *ws = ".";
  const char *state = getenv("ESCROW_STATE");
  char wsreal[PATH_MAX];
  struct run run;
  int c;

  // '+': stop at the first non-option, so the command's own flags are
  // never parsed as ours.
  while ((c = getopt_long(argc, argv, "+", opts, nullptr)) != -1) {
    switch (c) {
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
  if (optind >= argc)
    usage();
  if (!state || !*state)
    errx(2, "no state dir: pass --state DIR or set ESCROW_STATE");
  if (!realpath(ws, wsreal))
    err(1, "realpath %s", ws);

  overlay_prepare(&run, state, wsreal);
  warnx("run dir: %s", run.dir);
  int status = jail_run(&run, wsreal, &argv[optind]);
  if (!diff_print(&run, wsreal))
    warnx("some entries could not be compared (marked ?)");

  if (WIFSIGNALED(status))
    return 128 + WTERMSIG(status);
  return WEXITSTATUS(status);
}
