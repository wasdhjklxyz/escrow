#ifndef ESCROW_RECORD_H
#define ESCROW_RECORD_H

#include "proc.h"

#include <stddef.h>

// The proposal record, <run>/record: what the requester signs and every
// later signature covers. Text, one "key value" per line, fixed order:
//
//   escrow-record 1
//   id <run id>
//   time <UTC, ISO 8601>
//   workspace <abs path>
//   cmd <argv, each quoted like diff.c paths, space-separated>
//   exit <agent exit status>
//   escrow <escrow binary path>          \  attested by the requester:
//   role-policy <sha256 of policy file>   |  she runs escrow, so these say
//   role-env <role env store path>        |  what she ran, not what a
//   store <path>   (one per policy path) /   third party observed
//   roles <sha256 of the roles file>
//   base <tree hash of the workspace before the run>
//   changes <sha256 of <run>/changes>
//
// The values that come from outside (workspace, cmd) never contain a
// newline: the workspace path must need no quoting, and cmd is quoted.

struct record {
  char id[16];
  char time[32];
  char *workspace;
  char *cmd;
  int exit;
  char *escrow;
  char role_policy[SHA256_HEX + 1];
  char *role_env;
  char roles[SHA256_HEX + 1];
  char base[SHA256_HEX + 1];
  char changes[SHA256_HEX + 1];
  char **store;
  size_t nstore;
};

// Writes path with O_EXCL. argv is the agent's command line.
void record_write(const char *path, const struct record *r, char *const argv[]);

// Strict parse: exact order, no unknown or repeated keys, well-formed
// hashes. Exits with status 1 on any problem.
void record_read(const char *path, struct record *r);

// Frees what record_read allocated.
void record_free(struct record *r);

// C-style quoting for one value (the diff's rules): bytes that could
// forge or hide text on a terminal become \ooo; "" for empty. out must
// hold 4*strlen(s)+3 bytes.
void record_quote(char *out, const char *s);
// True if s would come out of record_quote unchanged (no quoting needed).
bool record_plain(const char *s);

#endif
