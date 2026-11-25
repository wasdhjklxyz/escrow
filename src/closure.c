#include "closure.h"

#include "apply.h"
#include "changes.h"
#include "proc.h"

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { OUT_MAX = 1 << 16 };

// Options on every nix call: no flake nixConfig honoured (it could add
// substituters or settings), no import-from-derivation (no building during
// eval), no lock file updates (no new inputs).
#define NIX_SAFE                                                               \
  "--no-update-lock-file", "--option", "accept-flake-config", "false",         \
      "--option", "allow-import-from-derivation", "false"

// Prefix for evaluating the agent-written tree: every proxy variable points
// at a closed port, so an eval-time fetch (builtins.fetchurl, fetchTarball,
// fetchGit over http) fails instead of carrying data out. The locked inputs
// resolve from the store: the base was evaluated first. Not covered: ssh
// git URLs and the DNS lookup they do (see docs/WRITEUP.md).
#define NO_FETCH                                                               \
  "env", "http_proxy=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9",    \
      "all_proxy=http://127.0.0.1:9", "HTTP_PROXY=http://127.0.0.1:9",         \
      "HTTPS_PROXY=http://127.0.0.1:9", "ALL_PROXY=http://127.0.0.1:9",        \
      "no_proxy=", "NO_PROXY="

static void skip(const char *why) {
  printf("\nclosure diff: skipped, %s\n", why);
}

// Runs argv; its stdout goes to out (NUL-terminated, trimmed of one final
// newline), its stderr to errs (if errs is null: shown, escaped, only on
// failure). Returns false if it failed or couldn't run.
static bool capture(char *const argv[], char *out, size_t n, FILE *errs) {
  FILE *o = tmpfile(), *e = errs ? errs : tmpfile();
  if (!o || !e)
    err(1, "tmpfile");
  out[0] = '\0';
  bool ok = run_cmd_err(argv, -1, fileno(o), fileno(e)) == 0;
  rewind(o);
  size_t got = fread(out, 1, n - 1, o);
  out[got] = '\0';
  // Output that doesn't fit is a failure, never a silently shorter string.
  if (got == n - 1 && getc(o) != EOF) {
    ok = false;
    out[0] = '\0';
  }
  if (got && out[got - 1] == '\n')
    out[got - 1] = '\0';
  fclose(o);
  if (!ok && !errs) {
    rewind(e);
    print_escaped(e);
  }
  if (!errs)
    fclose(e);
  return ok;
}

// The drvPath of nixosConfigurations.<name>'s toplevel in flake dir.
static bool drv_path(const char *dir, const char *name, bool agent_written,
                     char out[PATH_MAX]) {
  char ref[PATH_MAX + 128];
  snprintf(ref, sizeof ref,
           "path:%s#nixosConfigurations.%s.config.system.build.toplevel."
           "drvPath",
           dir, name);
  char *plain[] = {"nix", "eval", "--raw", NIX_SAFE, ref, nullptr};
  char *nofetch[] = {NO_FETCH, "nix", "eval", "--raw", NIX_SAFE, ref, nullptr};
  return capture(agent_written ? nofetch : plain, out, PATH_MAX, nullptr) &&
         strncmp(out, "/nix/store/", 11) == 0;
}

// A fixed-output derivation is the one kind that gets network inside the
// Nix sandbox (builtin:fetchurl, fetchgit, ...), so building one that the
// agent wrote could send workspace data anywhere. Refuse if `nix build
// --dry-run` would build (not substitute) any. Over-matching is fine: a
// false positive only skips the closure diff.
// True if drv is (or may be) fixed-output: any hash field anywhere in the
// whole `nix derivation show` output. Read in full, never through a fixed
// buffer: the agent controls the env and can pad it past any cap. Fails
// closed: if the output can't be had, it counts as fixed-output.
static bool is_fixed_output(const char *drv) {
  char *show[] = {"nix", "derivation", "show", (char *)drv, nullptr};
  FILE *o = tmpfile(), *e = tmpfile();
  struct stat st;
  if (!o || !e)
    err(1, "tmpfile");
  bool ok = run_cmd_err(show, -1, fileno(o), fileno(e)) == 0 &&
            fstat(fileno(o), &st) == 0;
  fclose(e);
  char *buf = ok ? malloc((size_t)st.st_size + 1) : nullptr;
  if (ok && !buf)
    err(1, "malloc");
  if (ok) {
    rewind(o);
    ok = fread(buf, 1, (size_t)st.st_size, o) == (size_t)st.st_size;
    buf[ok ? st.st_size : 0] = '\0';
  }
  fclose(o);
  bool fod = !ok || memmem(buf, (size_t)st.st_size, "outputHash", 10) ||
             memmem(buf, (size_t)st.st_size, "\"hashAlgo\"", 10) ||
             memmem(buf, (size_t)st.st_size, "\"hash\":", 7);
  free(buf);
  return fod;
}

static bool builds_fetcher(const char *drv, char *why, size_t n) {
  char ref[PATH_MAX + 8], line[PATH_MAX + 64];
  static char out[OUT_MAX];
  snprintf(ref, sizeof ref, "%s^*", drv);
  char *dry[] = {"nix", "build", "--dry-run", NIX_SAFE, ref, nullptr};
  FILE *errs = tmpfile();
  if (!errs)
    err(1, "tmpfile");
  if (!capture(dry, out, sizeof out, errs)) {
    snprintf(why, n, "nix build --dry-run failed");
    fclose(errs);
    return true;
  }
  rewind(errs);
  bool built = false, fetcher = false;
  while (!fetcher && fgets(line, sizeof line, errs)) {
    if (line[0] != ' ') {
      // Only the two headers nix prints are understood; anything else
      // (a changed format) fails closed rather than skipping the check.
      built = strstr(line, "will be built") != nullptr;
      if (!built && !strstr(line, "will be fetched")) {
        snprintf(why, n, "unrecognized nix build --dry-run output");
        fetcher = true;
      }
      continue;
    }
    char *p = line + strspn(line, " ");
    p[strcspn(p, "\n")] = '\0';
    size_t len = strlen(p);
    if (!built || len < 4 || strcmp(p + len - 4, ".drv") != 0)
      continue;
    if (is_fixed_output(p)) {
      snprintf(why, n, "it would build fixed-output derivation %s", p);
      fetcher = true;
    }
  }
  fclose(errs);
  return fetcher;
}

static bool build(const char *drv, char out[PATH_MAX]) {
  char ref[PATH_MAX + 8];
  snprintf(ref, sizeof ref, "%s^out", drv);
  char *argv[] = {"nix",    "build", "--no-link", "--print-out-paths",
                  NIX_SAFE, ref,     nullptr};
  return capture(argv, out, PATH_MAX, nullptr);
}

// `nix store diff-closures` hardcodes ANSI colours (SGR: ESC [ digits ; m)
// and uses UTF-8 arrows. Drop the colours, spell "→" and "∅" in ASCII, and
// escape everything else (print_escaped).
static void print_diff(FILE *in) {
  FILE *out = tmpfile();
  char *line = nullptr;
  size_t cap = 0;
  ssize_t len;
  if (!out)
    err(1, "tmpfile");
  while ((len = getline(&line, &cap, in)) > 0) {
    for (ssize_t i = 0; i < len; i++) {
      size_t k = line[i] == 0x1b && line[i + 1] == '['
                     ? 2 + strspn(line + i + 2, "0123456789;")
                     : 0;
      if (k && line[i + (ssize_t)k] == 'm') {
        i += (ssize_t)k;
      } else if (strncmp(line + i, "→", 3) == 0) {
        fputs("->", out);
        i += 2;
      } else if (strncmp(line + i, "∅", 3) == 0) {
        fputs("{}", out);
        i += 2;
      } else {
        putc(line[i], out);
      }
    }
  }
  free(line);
  rewind(out);
  print_escaped(out);
  fclose(out);
}

static void diff_config(const char *ws, const char *proposed,
                        const char *name) {
  char a[PATH_MAX], b[PATH_MAX], why[PATH_MAX + 64];
  char base_out[PATH_MAX], proposed_out[PATH_MAX];

  printf("\nclosure diff: nixosConfigurations.%s (building...)\n", name);
  fflush(stdout);
  if (!drv_path(ws, name, false, a) || !drv_path(proposed, name, true, b)) {
    printf("  evaluation failed\n");
    return;
  }
  if (builds_fetcher(b, why, sizeof why) ||
      builds_fetcher(a, why, sizeof why)) {
    printf("  refused: %s (it would have network)\n", why);
    return;
  }
  if (!build(a, base_out) || !build(b, proposed_out)) {
    printf("  build failed\n");
    return;
  }
  char *diff[] = {"nix",    "store",      "diff-closures",
                  base_out, proposed_out, nullptr};
  FILE *t = tmpfile();
  if (!t)
    err(1, "tmpfile");
  // ftell works: the child's stdout shares this file's offset.
  if (run_cmd(diff, -1, fileno(t)) != 0)
    printf("  nix store diff-closures failed\n");
  else if (ftell(t) == 0)
    printf("  no package version or size changes (not every change shows "
           "here: the file diff above is what is applied)\n");
  rewind(t);
  print_diff(t);
  fclose(t);
}

void closure_diff(const char *ws, const struct changeset *cs) {
  char path[PATH_MAX], ref[PATH_MAX + 32], tmp[PATH_MAX - 4]; // room for /ws
  char proposed[PATH_MAX], sandbox[64];
  static char names[OUT_MAX];

  snprintf(path, sizeof path, "%s/flake.nix", ws);
  if (access(path, F_OK) != 0)
    return;
  snprintf(path, sizeof path, "%s/flake.lock", ws);
  if (access(path, F_OK) != 0) {
    skip("no flake.lock (it would have to fetch inputs)");
    return;
  }
  for (size_t i = 0; i < cs->n; i++)
    if (strcmp(cs->v[i].path, "flake.lock") == 0) {
      skip("the change set touches flake.lock");
      return;
    }
  // Nix normally sandboxes builds; with it off, an agent-written builder
  // would run as us, with our files and network.
  char *show[] = {"nix", "config", "show", "sandbox", nullptr};
  if (!capture(show, sandbox, sizeof sandbox, nullptr)) {
    skip("can't run nix");
    return;
  }
  if (strcmp(sandbox, "true") != 0) {
    skip("nix's build sandbox is off (sandbox = true is required)");
    return;
  }

  snprintf(ref, sizeof ref, "path:%s#nixosConfigurations", ws);
  char *eval[] = {
      "nix",  "eval", "--json", NIX_SAFE, ref, "--apply", "builtins.attrNames",
      nullptr};
  if (!capture(eval, names, sizeof names, nullptr)) {
    skip("no nixosConfigurations");
    return;
  }

  const char *tmpdir = getenv("TMPDIR");
  int n = snprintf(tmp, sizeof tmp, "%s/escrow-review-XXXXXX",
                   tmpdir && *tmpdir ? tmpdir : "/tmp");
  if (n < 0 || n >= (int)sizeof tmp) {
    skip("TMPDIR is too long");
    return;
  }
  if (!mkdtemp(tmp))
    err(1, "mkdtemp %s", tmp);
  snprintf(proposed, sizeof proposed, "%s/ws", tmp);
  char *cp[] = {"cp",       "-a",     "--no-target-directory",
                (char *)ws, proposed, nullptr};
  if (run_cmd(cp, -1, -1) != 0 || apply_changes(cs, proposed) < 0) {
    remove_dir(tmp);
    {
      skip("couldn't materialize the proposal");
      return;
    }
  }
  // ["a","b"]: only plain attribute names are built, so a name can't
  // smuggle anything into a flake reference.
  for (char *s = strtok(names, "[\","); s; s = strtok(nullptr, "[\",")) {
    if (strcmp(s, "]") == 0)
      continue;
    if (!*s || strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "0123456789_-") != strlen(s)) {
      skip("a config name that isn't a plain identifier");
      continue;
    }
    diff_config(ws, proposed, s);
  }
  remove_dir(tmp);
}
