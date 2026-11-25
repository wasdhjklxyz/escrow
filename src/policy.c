#include "policy.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define STORE "/nix/store/"

// Nix's own checks (libstore/path.cc): the hash is 32 chars of nix-base32
// (no e, o, u, t), the name is [A-Za-z0-9+._?=-] and doesn't start with a
// '.'. Stricter than needed is fine: anything else is not a store path, and
// a '/' or ".." in a name would bind-mount something outside the store.
static bool store_path_ok(const char *s) {
  static const char b32[] = "0123456789abcdfghijklmnpqrsvwxyz";
  static const char name[] = "abcdefghijklmnopqrstuvwxyz"
                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-._?=";

  if (strncmp(s, STORE, strlen(STORE)) != 0)
    return false;
  s += strlen(STORE);
  if (strspn(s, b32) != 32 || s[32] != '-')
    return false;
  s += 33;
  return *s && *s != '.' && strspn(s, name) == strlen(s);
}

static void add(struct policy *p, const char *path, const char *file,
                size_t line) {
  struct stat st;

  if (!store_path_ok(path))
    errx(1, "%s:%zu: not a store path: %s", file, line, path);
  // lstat: the root binds exactly this path. A symlink would be followed
  // by the bind and could point anywhere.
  if (lstat(path, &st) < 0)
    err(1, "%s:%zu: %s", file, line, path);
  if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
    errx(1, "%s:%zu: %s is not a dir or regular file", file, line, path);
  char **s = reallocarray(p->store, p->n + 1, sizeof *s);
  if (!s)
    err(1, "reallocarray");
  p->store = s;
  if (!(p->store[p->n++] = strdup(path)))
    err(1, "strdup");
}

void policy_load(struct policy *p, const char *path) {
  char *buf = nullptr;
  size_t cap = 0, line = 0;
  ssize_t len;
  char *env = nullptr;

  *p = (struct policy){};
  FILE *f = fopen(path, "re");
  if (!f)
    err(1, "open %s", path);
  while ((len = getline(&buf, &cap, f)) >= 0) {
    line++;
    if (len > 0 && buf[len - 1] == '\n')
      buf[--len] = '\0';
    if (strlen(buf) != (size_t)len)
      errx(1, "%s:%zu: NUL byte", path, line);
    if (strncmp(buf, "store ", 6) == 0) {
      add(p, buf + 6, path, line);
    } else if (strncmp(buf, "env ", 4) == 0) {
      if (env)
        errx(1, "%s:%zu: second env line", path, line);
      if (!store_path_ok(buf + 4))
        errx(1, "%s:%zu: not a store path: %s", path, line, buf + 4);
      if (!(env = strdup(buf + 4)))
        err(1, "strdup");
    } else {
      errx(1, "%s:%zu: expected \"env PATH\" or \"store PATH\"", path, line);
    }
  }
  if (ferror(f))
    err(1, "read %s", path);
  if (fclose(f) == EOF)
    err(1, "close %s", path);
  free(buf);

  if (!env)
    errx(1, "%s: no env line", path);
  for (size_t i = 0; i < p->n; i++)
    if (strcmp(p->store[i], env) == 0)
      p->env = p->store[i];
  if (!p->env)
    errx(1, "%s: env %s is not in the store list", path, env);
  free(env);
}
