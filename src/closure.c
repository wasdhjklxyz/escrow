#include "closure.h"

#include "apply.h"
#include "changes.h"
#include "proc.h"

#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Runs argv, returns its stdout (first line, trimmed) in out, or false.
// Its stderr (nix's build chatter) is shown, escaped, only on failure.
static bool capture(char *const argv[], char *out, size_t n) {
  FILE *t = tmpfile(), *e = tmpfile();
  if (!t || !e)
    err(1, "tmpfile");
  bool ok = run_cmd_err(argv, -1, fileno(t), fileno(e)) == 0;
  if (!ok) {
    rewind(e);
    print_escaped(e);
  }
  fclose(e);
  rewind(t);
  if (ok && !fgets(out, (int)n, t))
    ok = false;
  fclose(t);
  out[strcspn(out, "\n")] = '\0';
  return ok;
}

// `nix store diff-closures` hardcodes ANSI colours (SGR: ESC [ digits/; m).
// Drop those; any other byte still goes through print_escaped.
static void print_without_sgr(FILE *in) {
  FILE *out = tmpfile();
  int c;
  if (!out)
    err(1, "tmpfile");
  while ((c = getc(in)) != EOF) {
    if (c == 0x1b) {
      int d = getc(in);
      if (d == '[') {
        while ((d = getc(in)) != EOF && (isdigit(d) || d == ';'))
          ;
        if (d == 'm')
          continue;
        putc(0x1b, out);
        putc('[', out);
      } else {
        putc(0x1b, out);
      }
      if (d != EOF)
        putc(d, out);
      continue;
    }
    putc(c, out);
  }
  rewind(out);
  print_escaped(out);
  fclose(out);
}

static bool build(const char *dir, const char *name, char out[PATH_MAX]) {
  char ref[PATH_MAX + 128];
  snprintf(ref, sizeof ref,
           "path:%s#nixosConfigurations.%s.config.system.build.toplevel", dir,
           name);
  char *argv[] = {"nix",
                  "build",
                  "--no-link",
                  "--print-out-paths",
                  "--no-update-lock-file",
                  "--option",
                  "accept-flake-config",
                  "false",
                  "--option",
                  "allow-import-from-derivation",
                  "false",
                  ref,
                  nullptr};
  return capture(argv, out, PATH_MAX);
}

void closure_diff(const char *ws, const struct changeset *cs) {
  char flake[PATH_MAX], names[4096], ref[PATH_MAX + 32];
  char tmp[PATH_MAX - 8], proposed[PATH_MAX];

  snprintf(flake, sizeof flake, "%s/flake.nix", ws);
  if (access(flake, F_OK) != 0)
    return;
  for (size_t i = 0; i < cs->n; i++) {
    if (strcmp(cs->v[i].path, "flake.lock") == 0) {
      printf("\nclosure diff: skipped, the change set touches flake.lock "
             "(building could fetch new inputs)\n");
      return;
    }
  }
  snprintf(ref, sizeof ref, "path:%s#nixosConfigurations", ws);
  char *eval[] = {"nix",      "eval",
                  "--json",   "--no-update-lock-file",
                  "--option", "accept-flake-config",
                  "false",    ref,
                  "--apply",  "builtins.attrNames",
                  nullptr};
  if (!capture(eval, names, sizeof names)) {
    printf("\nclosure diff: skipped, no nixosConfigurations\n");
    return;
  }

  const char *tmpdir = getenv("TMPDIR");
  snprintf(tmp, sizeof tmp, "%s/escrow-review-XXXXXX",
           tmpdir && *tmpdir ? tmpdir : "/tmp");
  if (!mkdtemp(tmp))
    err(1, "mkdtemp %s", tmp);
  snprintf(proposed, sizeof proposed, "%s/ws", tmp);
  char *cp[] = {"cp",       "-a",     "--no-target-directory",
                (char *)ws, proposed, nullptr};
  if (run_cmd(cp, -1, -1) != 0 || apply_changes(cs, proposed) < 0) {
    printf("\nclosure diff: skipped, couldn't materialize the proposal\n");
    remove_dir(tmp);
    return;
  }

  // ["a","b"]: config names are Nix attribute names. Only plain ones are
  // built, so a name can't smuggle anything into the flake reference.
  for (char *s = strtok(names, "[\","); s; s = strtok(nullptr, "[\",")) {
    char a[PATH_MAX], b[PATH_MAX];
    if (strcmp(s, "]") == 0)
      continue;
    if (strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  "0123456789_-") != strlen(s)) {
      printf("\nclosure diff: skipped config with an unusual name\n");
      continue;
    }
    printf("\nclosure diff, nixosConfigurations.%s (building...)\n", s);
    fflush(stdout);
    if (!build(ws, s, a) || !build(proposed, s, b)) {
      printf("  build failed; see the nix output above\n");
      continue;
    }
    char *diff[] = {"nix", "store", "diff-closures", a, b, nullptr};
    FILE *t = tmpfile();
    if (!t)
      err(1, "tmpfile");
    if (run_cmd(diff, -1, fileno(t)) != 0)
      printf("  nix store diff-closures failed\n");
    if (ftell(t) == 0)
      printf("  (no package or size changes)\n");
    rewind(t);
    print_without_sgr(t);
    fclose(t);
  }
  fflush(stdout);
  remove_dir(tmp);
}
