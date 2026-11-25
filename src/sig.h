#ifndef ESCROW_SIG_H
#define ESCROW_SIG_H

#include "proc.h"

#include <limits.h>
#include <stddef.h>

// Roles and SSH signatures. All crypto is OpenSSH's `ssh-keygen -Y`.
//
// Roles file, one principal per line ('#' comments and blank lines ok):
//   <principal> <role>[,<role>...] <keytype> <base64-key> [comment]
// principal: [a-z0-9._-]+, unique. roles: requester, reviewer, signer.
// keytype: an OpenSSH public key type from a fixed allowlist. Each key may
// appear once, so distinct principals always mean distinct keys.

enum { ROLE_REQUESTER = 1, ROLE_REVIEWER = 2, ROLE_SIGNER = 4 };

// Signature namespaces. propose, review and sign all sign the same record
// bytes and differ only here, so one step's signature can't be replayed
// as another's. apply signs the apply statement (cmd.c).
#define NS_PROPOSE "escrow-propose"
#define NS_REVIEW "escrow-review"
#define NS_SIGN "escrow-sign"
#define NS_APPLY "escrow-apply"

struct principal {
  char *name;
  unsigned roles;
};

struct roles {
  struct principal *v;
  size_t n;
  char sha[SHA256_HEX + 1]; // of the roles file
  char allowed[PATH_MAX];   // generated allowed_signers: /proc/<pid>/fd/<memfd>
};

// Exits with status 1 on any malformed line or failure. Once per process.
void roles_load(struct roles *r, const char *file);

// The roles file from --roles or $ESCROW_ROLES; exits with status 2 if
// neither is set.
const char *roles_path(const char *opt);

// Signs data_file with key (a private key, or a public key whose private
// half is in ssh-agent) under namespace ns, verifies the result against
// the roles, and only then links it in at sig_out (which must not exist).
// Returns the signing principal. Exits with status 1 on failure,
// including a key that isn't in the roles file.
const struct principal *sig_create(const struct roles *r, const char *key,
                                   const char *ns, const char *data_file,
                                   const char *sig_out);

// Returns the principal whose key made sig_file over data_file under ns,
// or nullptr after printing why.
const struct principal *sig_verify(const struct roles *r, const char *ns,
                                   const char *data_file, const char *sig_file);

const char *role_name(unsigned role);

#endif
