#ifndef ESCROW_PROC_H
#define ESCROW_PROC_H

#include <stddef.h>
#include <sys/types.h>

// Host-side helper processes. escrow implements no crypto: SHA-256 is
// coreutils sha256sum and signatures are OpenSSH ssh-keygen, found on PATH
// (the Nix package wraps escrow with both).

// Runs argv with stdin from in_fd and stdout to out_fd (-1: /dev/null for
// stdin, inherit for stdout). stderr is inherited. Returns the exit
// status (0..255), or 128+N if killed by signal N. Exits with status 1 if
// it can't be spawned.
int run_cmd(char *const argv[], int in_fd, int out_fd);

// write(2) until all n bytes are out (EINTR retried). 0 or -1.
int write_all(int fd, const void *buf, size_t n);

// A running sha256sum fed through a pipe.
struct sha256 {
  pid_t pid;
  int in;  // write the data here
  int out; // the hex digest comes back here
};

enum { SHA256_HEX = 64 };

// Exits with status 1 on any failure.
void sha256_open(struct sha256 *h);
void sha256_write(struct sha256 *h, const void *buf, size_t n);
// Closes the input, reads the digest into hex (NUL-terminated).
void sha256_close(struct sha256 *h, char hex[SHA256_HEX + 1]);

// sha256 of a whole file (opened O_NOFOLLOW).
void sha256_file(const char *path, char hex[SHA256_HEX + 1]);
void sha256_buf(const void *buf, size_t n, char hex[SHA256_HEX + 1]);

#endif
