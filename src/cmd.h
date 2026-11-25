#ifndef ESCROW_CMD_H
#define ESCROW_CMD_H

struct run;
struct policy;
struct roles;

// What a run needs to become a proposal (escrow ... --key KEY -- cmd).
struct propose {
  const char *key;
  const struct roles *roles;
  const char *state;
  const char *role_file; // the policy file
  const struct policy *policy;
  const char *ws;
  char *const *argv;
};

// After the run and the diff walk: writes <run>/record, has the requester
// sign it, logs `propose`. base is the workspace tree hash taken before
// the run. Exits with status 1 on failure.
void propose(const struct propose *p, const struct run *run, int status,
             const char *base);

// The subcommands; argv[0] is the subcommand name. Return the exit status.
int cmd_list(int argc, char *argv[]);
int cmd_review(int argc, char *argv[]);
int cmd_sign(int argc, char *argv[]);
int cmd_apply(int argc, char *argv[]);
int cmd_verify_log(int argc, char *argv[]);

#endif
