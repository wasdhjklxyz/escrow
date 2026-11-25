#include "changes.h"
#include "cmd.h"
#include "diff.h"
#include "jail.h"
#include "landlock.h"
#include "overlay.h"
#include "policy.h"
#include "sig.h"
#include "tree.h"

#include <err.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

[[noreturn]] static void usage(void) {
  fprintf(
      stderr,
      "usage: escrow --role POLICY [--key KEY --roles FILE] [--net]\n"
      "              [--workspace DIR] [--state DIR] -- <cmd> [args...]\n"
      "       escrow list [--state DIR]\n"
      "       escrow review <id> [--key KEY] [--state DIR] [--roles FILE]\n"
      "       escrow sign <id> --key KEY [--state DIR] [--roles FILE]\n"
      "       escrow apply <id> --key KEY [--state DIR] [--roles FILE]\n"
      "       escrow verify-log [--state DIR] [--roles FILE]\n"
      "  --role POLICY    role policy file (nix build .#role-<name>)\n"
      "  --key KEY        SSH key that signs (with --roles: run proposes)\n"
      "  --roles FILE     who may request, review, sign ($ESCROW_ROLES)\n"
      "  --net            share the host network (TCP 443 and DNS only)\n"
      "  --workspace DIR  directory the command sees as /work (default: .)\n"
      "  --state DIR      where runs and the log live ($ESCROW_STATE)\n"
      "run exit: the command's status (128+N if killed by signal N),\n"
      "      125 setup failed, 127 exec failed, 1 escrow error, 2 usage\n");
  exit(2);
}

int main(int argc, char *argv[]) {
  static const struct {
    const char *name;
    int (*fn)(int, char *[]);
  } cmds[] = {
      {"list", cmd_list},   {"review", cmd_review},         {"sign", cmd_sign},
      {"apply", cmd_apply}, {"verify-log", cmd_verify_log},
  };
  static const struct option opts[] = {
      {"role", required_argument, nullptr, 'r'},
      {"key", required_argument, nullptr, 'k'},
      {"roles", required_argument, nullptr, 'R'},
      {"net", no_argument, nullptr, 'n'},
      {"workspace", required_argument, nullptr, 'w'},
      {"state", required_argument, nullptr, 's'},
      {},
  };
  const char *ws = ".";
  const char *state = getenv("ESCROW_STATE");
  const char *role = nullptr, *key = nullptr, *roles_opt = nullptr;
  char wsreal[PATH_MAX], base[SHA256_HEX + 1], after[SHA256_HEX + 1];
  char changes_path[PATH_MAX];
  // static: reachable at exit, so LeakSanitizer doesn't flag them.
  static struct policy policy;
  static struct roles roles;
  struct changes_writer cw;
  struct run run;
  struct jail j = {.run = &run, .ws = wsreal, .policy = &policy};
  int c;

  // A closed stdout must be EPIPE, not death mid-walk or mid-apply (see
  // diff.c). Helpers get the default back (proc.c).
  signal(SIGPIPE, SIG_IGN);
  if (getuid() == 0 || geteuid() == 0)
    errx(1, "refusing to run as root");
  if (argc > 1)
    for (size_t i = 0; i < sizeof cmds / sizeof *cmds; i++)
      if (strcmp(argv[1], cmds[i].name) == 0)
        return cmds[i].fn(argc - 1, argv + 1);

  // '+': stop at the first non-option, so the command's own flags are
  // never parsed as ours.
  while ((c = getopt_long(argc, argv, "+", opts, nullptr)) != -1) {
    switch (c) {
    case 'r':
      role = optarg;
      break;
    case 'k':
      key = optarg;
      break;
    case 'R':
      roles_opt = optarg;
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
  // Fail closed: under --net only Landlock (with seccomp keeping sockets
  // to plain TCP/UDP) keeps the agent off other ports and the host's
  // abstract unix sockets (dbus, X11).
  j.landlock_abi = landlock_abi();
  if (j.net && j.landlock_abi < 10)
    errx(1, "--net needs Landlock ABI >= 10 (TCP and UDP port rules), have %d",
         j.landlock_abi);
  if (!realpath(ws, wsreal))
    err(1, "realpath %s", ws);
  policy_load(&policy, role);
  // Before the run: a proposal pins the tree the agent started from.
  bool proposable = false;
  if (key) {
    roles_load(&roles, roles_path(roles_opt));
    proposable = tree_hash(wsreal, base);
    if (!proposable)
      warnx("workspace can't be pinned: no proposal");
  }

  overlay_prepare(&run, state, wsreal);
  warnx("run dir: %s", run.dir);
  int status = jail_run(&j, &argv[optind]);
  warnx("agent output: %s", run.log);
  int n = snprintf(changes_path, sizeof changes_path, "%s/changes", run.dir);
  if (n < 0 || n >= (int)sizeof changes_path)
    errx(1, "path too long");
  changes_open(&cw, changes_path);
  if (!diff_print(&run, wsreal, &cw))
    warnx("some entries could not be compared (marked ?)");
  if (!changes_close(&cw) && key) {
    warnx("not proposable: %s", cw.why);
    proposable = false;
  }
  // After the walk, which read the live workspace for deletions.
  if (proposable && (!tree_hash(wsreal, after) || strcmp(base, after))) {
    warnx("not proposable: the workspace changed during the run");
    proposable = false;
  }

  int exit_status =
      WIFSIGNALED(status) ? 128 + WTERMSIG(status) : WEXITSTATUS(status);
  if (proposable) {
    struct propose p = {.key = key,
                        .roles = &roles,
                        .state = state,
                        .role_file = role,
                        .policy = &policy,
                        .ws = wsreal,
                        .argv = &argv[optind]};
    propose(&p, &run, exit_status, base);
  } else if (key) {
    return 1;
  }
  return exit_status;
}
