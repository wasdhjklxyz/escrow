#include "record.h"

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool unsafe(unsigned char c) {
  return c <= ' ' || c >= 0x7f || c == '"' || c == '\\';
}

bool record_plain(const char *s) {
  if (!*s)
    return false;
  for (const unsigned char *p = (const unsigned char *)s; *p; p++)
    if (unsafe(*p))
      return false;
  return true;
}

void record_quote(char *out, const char *s) {
  if (record_plain(s)) {
    strcpy(out, s);
    return;
  }
  *out++ = '"';
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (*p == '"' || *p == '\\') {
      *out++ = '\\';
      *out++ = (char)*p;
    } else if (unsafe(*p) && *p != ' ') {
      out += sprintf(out, "\\%03o", *p);
    } else {
      *out++ = (char)*p;
    }
  }
  *out++ = '"';
  *out = '\0';
}

void record_write(const char *path, const struct record *r,
                  char *const argv[]) {
  int fd =
      open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  FILE *f = fd < 0 ? nullptr : fdopen(fd, "w");
  if (!f)
    err(1, "open %s", path);
  fprintf(f, "escrow-record 1\nid %s\ntime %s\nworkspace %s\ncmd", r->id,
          r->time, r->workspace);
  for (char *const *a = argv; *a; a++) {
    char *q = record_quoted(*a);
    fprintf(f, " %s", q);
    free(q);
  }
  fprintf(f,
          "\nexit %d\nnet %d\nenv %s\nescrow %s\nrole-policy %s\nrole-env %s\n",
          r->exit, r->net, r->env && *r->env ? r->env : "-", r->escrow,
          r->role_policy, r->role_env);
  for (size_t i = 0; i < r->nstore; i++)
    fprintf(f, "store %s\n", r->store[i]);
  fprintf(f, "roles %s\nbase %s\nchanges %s\n", r->roles, r->base, r->changes);
  if (fflush(f) == EOF || ferror(f) || fsync(fd) < 0 || fclose(f) == EOF)
    err(1, "write %s", path);
}

// Printable ASCII only: these fields are shown to the reviewer and signer,
// and a requester can write (and re-sign) any record she likes.
static bool printable(const char *s) {
  for (const unsigned char *p = (const unsigned char *)s; *p; p++)
    if (*p < 0x20 || *p >= 0x7f)
      return false;
  return true;
}

static bool hex64(const char *s) {
  return strlen(s) == SHA256_HEX && strspn(s, "0123456789abcdef") == SHA256_HEX;
}

void record_read(const char *path, struct record *r) {
  static const char *const order[] = {
      "escrow-record", "id",  "time",   "workspace",   "cmd",     "exit",
      "net",           "env", "escrow", "role-policy", "role-env"};
  char *buf = nullptr;
  size_t cap = 0, line = 0;
  ssize_t len;
  enum { HEAD, STORE, ROLES, BASE, CHANGES, DONE } tail = HEAD;

  *r = (struct record){};
  FILE *f = fopen(path, "re");
  if (!f)
    err(1, "open %s", path);
  while ((len = getline(&buf, &cap, f)) >= 0) {
    if (len == 0 || buf[len - 1] != '\n')
      errx(1, "%s:%zu: unterminated line", path, line + 1);
    buf[--len] = '\0';
    if ((size_t)len != strlen(buf))
      errx(1, "%s:%zu: NUL byte", path, line + 1);
    if (!printable(buf))
      errx(1, "%s:%zu: control or non-ASCII byte", path, line + 1);
    char *sp = strchr(buf, ' ');
    if (!sp)
      errx(1, "%s:%zu: expected \"key value\"", path, line + 1);
    *sp = '\0';
    const char *k = buf, *v = sp + 1;
    if (line < sizeof order / sizeof *order) {
      if (strcmp(k, order[line]) != 0)
        errx(1, "%s:%zu: expected key %s", path, line + 1, order[line]);
    }
    char *dup = strdup(v);
    if (!dup)
      err(1, "strdup");
    switch (line++) {
    case 0:
      if (strcmp(v, "1") != 0)
        errx(1, "%s: unsupported record version %s", path, v);
      free(dup);
      continue;
    case 1:
      if (strlen(v) != 6 || strspn(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
                                      "klmnopqrstuvwxyz0123456789") != 6)
        errx(1, "%s: bad id", path);
      strcpy(r->id, v);
      free(dup);
      continue;
    case 2:
      if (strlen(v) >= sizeof r->time)
        errx(1, "%s: bad time", path);
      strcpy(r->time, v);
      free(dup);
      continue;
    case 3:
      if (v[0] != '/' || !record_plain(v) || v[strlen(v) - 1] == '/')
        errx(1, "%s: bad workspace", path);
      r->workspace = dup;
      continue;
    case 4:
      r->cmd = dup;
      continue;
    case 5: {
      char *end;
      long e = strtol(v, &end, 10);
      if (*end || e < 0 || e > 255)
        errx(1, "%s: bad exit", path);
      r->exit = (int)e;
      free(dup);
      continue;
    }
    case 6:
      if (strcmp(v, "0") != 0 && strcmp(v, "1") != 0)
        errx(1, "%s: bad net", path);
      r->net = v[0] == '1';
      free(dup);
      continue;
    case 7:
      // "-" or variable names, one space apart (validated by main.c).
      if (strspn(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789_ -") != strlen(v) ||
          !*v)
        errx(1, "%s: bad env", path);
      r->env = dup;
      continue;
    case 8:
      r->escrow = dup;
      continue;
    case 9:
      if (!hex64(v))
        errx(1, "%s: bad role-policy", path);
      strcpy(r->role_policy, v);
      free(dup);
      continue;
    case 10:
      r->role_env = dup;
      tail = STORE;
      continue;
    }
    if (tail == STORE && strcmp(k, "store") == 0) {
      char **s = reallocarray(r->store, r->nstore + 1, sizeof *s);
      if (!s)
        err(1, "reallocarray");
      r->store = s;
      s[r->nstore++] = dup;
      continue;
    }
    free(dup);
    if ((tail == STORE || tail == ROLES) && strcmp(k, "roles") == 0 &&
        hex64(v)) {
      strcpy(r->roles, v);
      tail = BASE;
    } else if (tail == BASE && strcmp(k, "base") == 0 && hex64(v)) {
      strcpy(r->base, v);
      tail = CHANGES;
    } else if (tail == CHANGES && strcmp(k, "changes") == 0 && hex64(v)) {
      strcpy(r->changes, v);
      tail = DONE;
    } else {
      errx(1, "%s:%zu: unexpected or malformed %s", path, line, k);
    }
  }
  if (ferror(f) || fclose(f) == EOF)
    err(1, "read %s", path);
  free(buf);
  if (tail != DONE)
    errx(1, "%s: truncated record", path);
}

void record_free(struct record *r) {
  free(r->workspace);
  free(r->cmd);
  free(r->env);
  free(r->escrow);
  free(r->role_env);
  for (size_t i = 0; i < r->nstore; i++)
    free(r->store[i]);
  free(r->store);
  *r = (struct record){};
}

char *record_quoted(const char *s) {
  char *q = malloc(4 * strlen(s) + 3);
  if (!q)
    err(1, "malloc");
  record_quote(q, s);
  return q;
}
