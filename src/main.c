#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "diff.h"
#include "jail.h"
#include "overlay.h"

[[noreturn]] static void usage(void) {
  fprintf(stderr, "usage: escrow [--workspace DIR] [--state DIR] -- <cmd> "
                  "[args...]\n");
  exit(2);
}

int main(int argc, char *argv[]) {
  static const struct option opts[] = {
      {"workspace", required_argument, NULL, 'w'},
      {"state", required_argument, NULL, 's'},
      {"help", no_argument, NULL, 'h'},
      {},
  };
  const char *workspace = ".";
  const char *state = NULL;
  int c;
  /* '+': stop at the first non-option so the command's own flags pass
   * through untouched. */
  while ((c = getopt_long(argc, argv, "+w:s:h", opts, NULL)) != -1) {
    switch (c) {
    case 'w':
      workspace = optarg;
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

  /* No implicit default: where change sets live is a deployment decision. */
  if (state == NULL || state[0] == '\0')
    state = getenv("ESCROW_STATE");
  if (state == NULL || state[0] == '\0')
    errx(2, "no state dir: pass --state DIR or set ESCROW_STATE");

  static struct overlay ov;
  overlay_prepare(&ov, workspace, state);
  fprintf(stderr, "escrow: run %s\n", ov.run);

  pid_t pid = jail_spawn(&ov, &argv[optind]);
  int status = jail_wait(pid);
  diff_print(ov.upper, ov.lower, stdout);
  return status;
}
