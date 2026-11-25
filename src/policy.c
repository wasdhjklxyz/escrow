#include "policy.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define STORE "/nix/store/"
#define HASH_LEN 32
#define STORE_KEY "store "
#define ENV_KEY "env "

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
  if (strspn(s, b32) != HASH_LEN || s[HASH_LEN] != '-')
    return false;
  s += HASH_LEN + 1;
  return *s && *s != '.' && strspn(s, name) == strlen(s);
}

static void add_store(struct policy *p, const char *path, const char *file,
                      size_t line) {
  struct stat st;

  if (!store_path_ok(path))
    errx(1, "%s:%zu: not a store path: %s", file, line, path);
  for (size_t i = 0; i < p->nstore; i++)
    if (strcmp(p->store[i], path) == 0)
      errx(1, "%s:%zu: duplicate store path: %s", file, line, path);
  // lstat: the root binds exactly this path. A symlink would be followed
  // by the bind and could point anywhere.
  if (lstat(path, &st) < 0)
    err(1, "%s:%zu: %s", file, line, path);
  if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
    errx(1, "%s:%zu: %s is not a dir or regular file", file, line, path);
  char **s = reallocarray(p->store, p->nstore + 1, sizeof *s);
  if (!s)
    err(1, "reallocarray");
  p->store = s;
  if (!(p->store[p->nstore++] = strdup(path)))
    err(1, "strdup");
}

void policy_load(struct policy *p, const char *file) {
  char *buf = nullptr;
  size_t cap = 0, line = 0;
  ssize_t len;
  char *env = nullptr;

  *p = (struct policy){};
  FILE *f = fopen(file, "re");
  if (!f)
    err(1, "open %s", file);
  while ((len = getline(&buf, &cap, f)) >= 0) {
    line++;
    if (len > 0 && buf[len - 1] == '\n')
      buf[--len] = '\0';
    if (strlen(buf) != (size_t)len)
      errx(1, "%s:%zu: NUL byte", file, line);
    if (strncmp(buf, STORE_KEY, strlen(STORE_KEY)) == 0) {
      add_store(p, buf + strlen(STORE_KEY), file, line);
    } else if (strncmp(buf, ENV_KEY, strlen(ENV_KEY)) == 0) {
      if (env)
        errx(1, "%s:%zu: second env line", file, line);
      // Validated by matching a store line below.
      if (!(env = strdup(buf + strlen(ENV_KEY))))
        err(1, "strdup");
    } else {
      errx(1, "%s:%zu: expected \"env PATH\" or \"store PATH\"", file, line);
    }
  }
  if (ferror(f))
    err(1, "read %s", file);
  if (fclose(f) == EOF)
    err(1, "close %s", file);
  free(buf);

  if (!env)
    errx(1, "%s: no env line", file);
  for (size_t i = 0; i < p->nstore; i++)
    if (strcmp(p->store[i], env) == 0)
      p->env = p->store[i];
  if (!p->env)
    errx(1, "%s: env %s is not in the store list", file, env);
  free(env);
}
