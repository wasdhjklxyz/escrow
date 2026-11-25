#include "sig.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *const keytypes[] = {
    "ssh-ed25519",
    "sk-ssh-ed25519@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-rsa",
};

static const char *allowed_file;

static void unlink_allowed(void) {
  if (allowed_file)
    unlink(allowed_file);
}

const char *role_name(unsigned role) {
  return role == ROLE_REQUESTER  ? "requester"
         : role == ROLE_REVIEWER ? "reviewer"
                                 : "signer";
}

const char *roles_path(const char *opt) {
  const char *p = opt ? opt : getenv("ESCROW_ROLES");
  if (!p || !*p)
    errx(2, "no roles file: pass --roles FILE or set ESCROW_ROLES");
  return p;
}

static unsigned parse_roles(char *s) {
  unsigned roles = 0;
  for (char *tok = strtok(s, ","); tok; tok = strtok(nullptr, ",")) {
    if (strcmp(tok, "requester") == 0)
      roles |= ROLE_REQUESTER;
    else if (strcmp(tok, "reviewer") == 0)
      roles |= ROLE_REVIEWER;
    else if (strcmp(tok, "signer") == 0)
      roles |= ROLE_SIGNER;
    else
      return 0;
  }
  return roles;
}

void roles_load(struct roles *r, const char *file) {
  char *buf = nullptr, **keys = nullptr;
  size_t cap = 0, line = 0;
  ssize_t len;

  *r = (struct roles){};
  sha256_file(file, r->sha);
  FILE *in = fopen(file, "re");
  if (!in)
    err(1, "open %s", file);
  const char *tmpdir = getenv("TMPDIR");
  snprintf(r->allowed, sizeof r->allowed, "%s/escrow-allowed-XXXXXX",
           tmpdir && *tmpdir ? tmpdir : "/tmp");
  int fd = mkstemp(r->allowed);
  if (fd < 0)
    err(1, "mkstemp %s", r->allowed);
  allowed_file = r->allowed;
  if (atexit(unlink_allowed) != 0)
    errx(1, "atexit");
  FILE *out = fdopen(fd, "w");
  if (!out)
    err(1, "fdopen");

  while ((len = getline(&buf, &cap, in)) >= 0) {
    line++;
    if (len > 0 && buf[len - 1] == '\n')
      buf[--len] = '\0';
    if ((size_t)len != strlen(buf))
      errx(1, "%s:%zu: NUL byte", file, line);
    char *p = buf + strspn(buf, " \t");
    if (!*p || *p == '#')
      continue;
    char *name = strtok(p, " \t"), *roles = strtok(nullptr, " \t");
    char *type = strtok(nullptr, " \t"), *key = strtok(nullptr, " \t");
    if (!name || !roles || !type || !key)
      errx(1, "%s:%zu: expected <principal> <roles> <keytype> <key>", file,
           line);
    if (strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789._-") !=
            strlen(name) ||
        strlen(name) > 64)
      errx(1, "%s:%zu: principal must match [a-z0-9._-]{1,64}", file, line);
    unsigned rl = parse_roles(roles);
    if (!rl)
      errx(1, "%s:%zu: roles are requester, reviewer, signer", file, line);
    bool known = false;
    for (size_t i = 0; i < sizeof keytypes / sizeof *keytypes; i++)
      known |= strcmp(type, keytypes[i]) == 0;
    if (!known)
      errx(1, "%s:%zu: key type %s not allowed", file, line, type);
    if (strspn(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789+/=") != strlen(key))
      errx(1, "%s:%zu: key is not base64", file, line);
    for (size_t i = 0; i < r->n; i++) {
      if (strcmp(r->v[i].name, name) == 0)
        errx(1, "%s:%zu: principal %s listed twice", file, line, name);
      if (strcmp(keys[i], key) == 0)
        errx(1, "%s:%zu: key of %s already belongs to %s", file, line, name,
             r->v[i].name);
    }
    struct principal *v = reallocarray(r->v, r->n + 1, sizeof *v);
    char **k = reallocarray(keys, r->n + 1, sizeof *k);
    if (!v || !k)
      err(1, "reallocarray");
    r->v = v;
    keys = k;
    if (!(v[r->n].name = strdup(name)) || !(keys[r->n] = strdup(key)))
      err(1, "strdup");
    v[r->n].roles = rl;
    r->n++;
    if (fprintf(out, "%s %s %s\n", name, type, key) < 0)
      err(1, "write %s", r->allowed);
  }
  if (ferror(in) || fclose(in) == EOF)
    err(1, "read %s", file);
  if (fclose(out) == EOF)
    err(1, "write %s", r->allowed);
  for (size_t i = 0; i < r->n; i++)
    free(keys[i]);
  free(keys);
  free(buf);
  if (r->n == 0)
    errx(1, "%s: no principals", file);
}

static int open_ro(const char *path) {
  int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    err(1, "open %s", path);
  return fd;
}

const struct principal *sig_verify(const struct roles *r, const char *ns,
                                   const char *data_file,
                                   const char *sig_file) {
  char name[128] = "";
  // find-principals only matches the key: it checks no signature.
  char *find[] = {"ssh-keygen", "-q",
                  "-Y",         "find-principals",
                  "-s",         (char *)sig_file,
                  "-f",         (char *)r->allowed,
                  nullptr};
  FILE *t = tmpfile();
  if (!t)
    err(1, "tmpfile");
  if (run_cmd(find, -1, fileno(t)) != 0) {
    warnx("%s: signed by no key in the roles file", sig_file);
    fclose(t);
    return nullptr;
  }
  rewind(t);
  if (!fgets(name, sizeof name, t)) {
    fclose(t);
    warnx("%s: no principal", sig_file);
    return nullptr;
  }
  fclose(t);
  name[strcspn(name, "\n")] = '\0';
  const struct principal *p = nullptr;
  for (size_t i = 0; i < r->n; i++)
    if (strcmp(r->v[i].name, name) == 0)
      p = &r->v[i];
  if (!p) {
    warnx("%s: unknown principal", sig_file);
    return nullptr;
  }
  char *verify[] = {
      "ssh-keygen", "-q",    "-Y", "verify",   "-f", (char *)r->allowed,
      "-I",         p->name, "-n", (char *)ns, "-s", (char *)sig_file,
      nullptr};
  int in = open_ro(data_file), null = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (null < 0)
    err(1, "open /dev/null");
  int st = run_cmd(verify, in, null);
  close(in);
  close(null);
  if (st != 0) {
    warnx("%s: bad signature (namespace %s)", sig_file, ns);
    return nullptr;
  }
  return p;
}

const struct principal *sig_create(const struct roles *r, const char *key,
                                   const char *ns, const char *data_file,
                                   const char *sig_out) {
  char tmp[PATH_MAX];
  char *sign[] = {"ssh-keygen", "-q", "-Y",       "sign", "-f",
                  (char *)key,  "-n", (char *)ns, nullptr};

  // stdin -> stdout: ssh-keygen never writes or skips a <file>.sig itself.
  int n = snprintf(tmp, sizeof tmp, "%s.tmp-XXXXXX", sig_out);
  if (n < 0 || n >= (int)sizeof tmp)
    errx(1, "path too long: %s", sig_out);
  int out = mkstemp(tmp);
  if (out < 0)
    err(1, "mkstemp %s", tmp);
  int in = open_ro(data_file);
  int st = run_cmd(sign, in, out);
  close(in);
  if (close(out) < 0)
    err(1, "close %s", tmp);
  if (st != 0) {
    unlink(tmp);
    errx(1, "ssh-keygen -Y sign failed (key %s)", key);
  }
  const struct principal *p = sig_verify(r, ns, data_file, tmp);
  if (!p) {
    unlink(tmp);
    errx(1, "the new signature doesn't verify against the roles file");
  }
  if (link(tmp, sig_out) < 0) {
    int e = errno;
    unlink(tmp);
    (errno = e), err(1, "link %s", sig_out);
  }
  unlink(tmp);
  return p;
}
