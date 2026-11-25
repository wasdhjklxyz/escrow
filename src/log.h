#ifndef ESCROW_LOG_H
#define ESCROW_LOG_H

#include "proc.h"

#include <stddef.h>

// <state>/log: append-only, one event per line, each line pinning the
// hash of the one before it:
//
//   <seq> <time> <event> <id> <principal> <record-sha> <sig-sha> <extra>
//         <roles-sha> <prev-line-sha>
//
// event: propose | review | sign | apply. sig-sha is the sha256 of
// <run>/<seq>-<event>.sig. extra is the post-apply tree hash for apply,
// "-" otherwise. prev of line 1 is 64 zeros; a line's hash is the sha256
// of its text including the "\n". The chain makes edits and reordering
// detectable, not truncation: an auditor compares the head hash
// (verify-log prints it) with one kept elsewhere.

struct log_line {
  unsigned long seq;
  char time[32];
  char event[16];
  char id[16];
  char principal[72];
  char record[SHA256_HEX + 1];
  char sig[SHA256_HEX + 1];
  char extra[SHA256_HEX + 1];
  char roles[SHA256_HEX + 1];
  char prev[SHA256_HEX + 1];
  char hash[SHA256_HEX + 1]; // computed, not stored
};

struct log {
  int fd; // <state>/log, flock(LOCK_EX) held until exit
  struct log_line *v;
  size_t n;
};

// Opens (creating) and locks the log, then parses every line. Malformed
// lines exit with status 1. The chain itself is checked by log_verify.
void log_open(struct log *l, const char *state);

// Fills seq, time and prev, appends the line (fsync'd), and adds it to l.
void log_append(struct log *l, struct log_line *line);

// The seq the next appended line will get.
unsigned long log_next_seq(const struct log *l);

// The last line for id with this event, or nullptr.
const struct log_line *log_find(const struct log *l, const char *id,
                                const char *event);

#endif
