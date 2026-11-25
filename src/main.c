#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "diff.h"
#include "jail.h"
#include "overlay.h"

[[noreturn]] static void usage(void) {
  fprintf(stderr, "usage: escrow [--workspace DIR] -- <cmd> [args...]\n");
  exit(2);
}

int main(int argc, char *argv[]) {
  static const struct option opts[] = {
      {"workspace", required_argument, NULL, 'w'},
      {"help", no_argument, NULL, 'h'},
      {},
  };
  const char *workspace = ".";
  int c;
  /* '+': stop at the first non-option so the command's own flags pass
   * through untouched. */
  while ((c = getopt_long(argc, argv, "+w:h", opts, NULL)) != -1) {
    switch (c) {
    case 'w':
      workspace = optarg;
      break;
    default:
      usage();
    }
  }
  if (optind >= argc)
    usage();

  static struct overlay ov;
  overlay_prepare(&ov, workspace);
  fprintf(stderr, "escrow: run %s\n", ov.run);

  pid_t pid = jail_spawn(&ov, &argv[optind]);
  int status = jail_wait(pid);
  diff_print(ov.upper, ov.lower, stdout);
  return status;
}
