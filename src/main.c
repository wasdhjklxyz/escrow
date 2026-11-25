#include "diff.h"
#include "jail.h"
#include "overlay.h"

#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

[[noreturn]] static void usage(void) {
  fprintf(stderr,
          "usage: escrow [--workspace DIR] [--state DIR] -- <cmd> [args...]\n"
          "  --workspace DIR  directory the command sees (default: .)\n"
          "  --state DIR      where runs are kept (default: $ESCROW_STATE)\n");
  exit(2);
}

int main(int argc, char *argv[]) {
  static const struct option opts[] = {
      {"workspace", required_argument, nullptr, 'w'},
      {"state", required_argument, nullptr, 's'},
      {"help", no_argument, nullptr, 'h'},
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
    err(1, "workspace %s", ws);

  overlay_prepare(&run, state, wsreal);
  int st = jail_run(&run, wsreal, &argv[optind]);
  bool complete = diff_print(run.upper, wsreal);
  if (!complete)
    warnx("some entries could not be compared (marked ?)");
  warnx("run dir: %s", run.dir);

  if (WIFSIGNALED(st))
    return 128 + WTERMSIG(st);
  return WEXITSTATUS(st);
}
