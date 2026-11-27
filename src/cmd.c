#include "cmd.h"

#include "apply.h"
#include "changes.h"
#include "closure.h"
#include "log.h"
#include "overlay.h"
#include "policy.h"
#include "proc.h"
#include "record.h"
#include "sig.h"
#include "tree.h"

// Log events, one per step. A line's signature is <run>/<seq>-<event>.sig.
#define EV_PROPOSE "propose"
#define EV_REVIEW "review"
#define EV_SIGN "sign"
#define EV_APPLY "apply"

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static void join(char out[PATH_MAX], const char *fmt, const char *a,
                 const char *b) {
  int n = snprintf(out, PATH_MAX, fmt, a, b);
  if (n < 0 || n >= PATH_MAX)
    errx(1, "path too long");
}

static void sig_path(char out[PATH_MAX], const char *dir, unsigned long seq,
                     const char *event) {
  int n = snprintf(out, PATH_MAX, "%s/%lu-%s.sig", dir, seq, event);
  if (n < 0 || n >= PATH_MAX)
    errx(1, "path too long");
}

static const char *state_dir(const char *opt) {
  const char *s = opt ? opt : getenv("ESCROW_STATE");
  if (!s || !*s)
    errx(2, "no state dir: pass --state DIR or set ESCROW_STATE");
  return s;
}

// ---------------------------------------------------------------- propose

void propose(const struct propose *p, const struct run *run, int status,
             const char *base) {
  struct record r = {};
  char record_path[PATH_MAX], changes_path[PATH_MAX], sig[PATH_MAX];
  char exe[PATH_MAX], record_sha[SHA256_HEX + 1];
  static struct log log; // static: reachable at exit, for LeakSanitizer
  time_t now = time(nullptr);

  if (!record_plain(p->ws))
    errx(1, "workspace path %s needs quoting; can't go in a record", p->ws);
  snprintf(r.id, sizeof r.id, "%s", strrchr(run->dir, '/') + 1);
  strftime(r.time, sizeof r.time, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
  r.workspace = (char *)p->ws;
  r.exit = status;
  r.net = p->net;
  char envs[1024] = "";
  for (char *const *e = p->pass_env; e && *e; e++) {
    size_t len = strlen(envs);
    int n = snprintf(envs + len, sizeof envs - len, "%s%s", len ? " " : "", *e);
    if (n < 0 || (size_t)n >= sizeof envs - len)
      errx(1, "--env names too long for the record");
  }
  r.env = envs;
  if (!realpath("/proc/self/exe", exe))
    err(1, "realpath /proc/self/exe");
  char *qexe = record_quoted(exe);
  r.escrow = qexe;
  // The policy is usually a nix build result link: hash what it points at.
  char role_real[PATH_MAX];
  if (!realpath(p->role_file, role_real))
    err(1, "realpath %s", p->role_file);
  sha256_file(role_real, r.role_policy);
  r.role_env = (char *)p->policy->env;
  r.store = p->policy->store;
  r.nstore = p->policy->nstore;
  strcpy(r.roles, p->roles->sha);
  strcpy(r.base, base);
  join(changes_path, "%s/%s", run->dir, "changes");
  sha256_file(changes_path, r.changes);
  join(record_path, "%s/%s", run->dir, "record");
  record_write(record_path, &r, p->argv);
  sha256_file(record_path, record_sha);
  free(qexe);

  log_open(&log, p->state, true);
  unsigned long seq = log_next_seq(&log);
  sig_path(sig, run->dir, seq, EV_PROPOSE);
  const struct principal *who =
      sig_create(p->roles, p->key, NS_PROPOSE, record_path, sig);
  if (!(who->roles & ROLE_REQUESTER)) {
    unlink(sig);
    errx(1, "%s is not a requester", who->name);
  }
  struct log_line line = {};
  snprintf(line.event, sizeof line.event, EV_PROPOSE);
  snprintf(line.id, sizeof line.id, "%s", r.id);
  snprintf(line.principal, sizeof line.principal, "%s", who->name);
  strcpy(line.record, record_sha);
  sha256_file(sig, line.sig);
  strcpy(line.extra, "-");
  strcpy(line.roles, p->roles->sha);
  log_append(&log, &line);
  warnx("proposed %s as %s", r.id, who->name);
}

// ---------------------------------------------------------- verification

struct proposal {
  char dir[PATH_MAX];
  char record_path[PATH_MAX];
  char changes_path[PATH_MAX];
  char record_sha[SHA256_HEX + 1];
  struct record rec;
  struct changeset cs;
  const struct principal *requester, *reviewer, *signer;
};

// Checks one logged step for id: the line's sig file is the one pinned,
// it verifies under ns over data_file, and its principal is the logged
// one and holds role. Returns the principal.
static const struct principal *check_step(const struct roles *roles,
                                          const char *dir,
                                          const struct log_line *line,
                                          const char *ns, const char *data_file,
                                          unsigned role) {
  char sig[PATH_MAX], sha[SHA256_HEX + 1];

  sig_path(sig, dir, line->seq, line->event);
  sha256_file(sig, sha);
  if (strcmp(sha, line->sig) != 0)
    errx(1, "%s: not the signature log line %lu pinned", sig, line->seq);
  const struct principal *p = sig_verify(roles, ns, data_file, sig);
  if (!p)
    errx(1, "log line %lu: signature doesn't verify", line->seq);
  if (strcmp(p->name, line->principal) != 0)
    errx(1, "log line %lu: signed by %s, logged as %s", line->seq, p->name,
         line->principal);
  if (!(p->roles & role))
    errx(1, "log line %lu: %s is not a %s", line->seq, p->name,
         role_name(role));
  if (strcmp(line->roles, roles->sha) != 0)
    errx(1, "log line %lu: made under roles file sha256 %s, not this one",
         line->seq, line->roles);
  return p;
}

static void check_id(const char *id) {
  if (strlen(id) != 6 ||
      strspn(id, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                 "0123456789") != 6)
    errx(2, "bad proposal id %s", id);
}

// Loads and fully re-verifies proposal id from its files, using the log
// only to find which signature files are pinned.
static void load(struct proposal *p, const struct log *log,
                 const struct roles *roles, const char *state, const char *id) {
  char sha[SHA256_HEX + 1];

  changes_free(&p->cs);
  record_free(&p->rec);
  *p = (struct proposal){};
  check_id(id);
  const struct log_line *prop = log_find(log, id, EV_PROPOSE);
  if (!prop)
    errx(1, "no proposal %s in the log", id);
  join(p->dir, "%s/runs/%s", state, id);
  join(p->record_path, "%s/%s", p->dir, "record");
  join(p->changes_path, "%s/%s", p->dir, "changes");
  sha256_file(p->record_path, p->record_sha);
  if (strcmp(p->record_sha, prop->record) != 0)
    errx(1, "%s: changed since it was proposed", p->record_path);
  record_read(p->record_path, &p->rec);
  if (strcmp(p->rec.id, id) != 0)
    errx(1, "%s: record is for %s", p->record_path, p->rec.id);
  if (strcmp(p->rec.roles, roles->sha) != 0)
    errx(1,
         "proposal %s was made under roles file sha256 %s, not this one (%s): "
         "pass the roles file in effect then",
         id, p->rec.roles, roles->sha);
  sha256_file(p->changes_path, sha);
  if (strcmp(sha, p->rec.changes) != 0)
    errx(1, "%s: not the change set the record pins", p->changes_path);
  changes_read(p->changes_path, &p->cs);
  p->requester = check_step(roles, p->dir, prop, NS_PROPOSE, p->record_path,
                            ROLE_REQUESTER);
  const struct log_line *rev = log_find(log, id, EV_REVIEW);
  if (rev)
    p->reviewer = check_step(roles, p->dir, rev, NS_REVIEW, p->record_path,
                             ROLE_REVIEWER);
  const struct log_line *sgn = log_find(log, id, EV_SIGN);
  if (sgn)
    p->signer =
        check_step(roles, p->dir, sgn, NS_SIGN, p->record_path, ROLE_SIGNER);
  // Separation of duties, from the signatures themselves: a requester can
  // append log lines, so their mere presence proves nothing. Every command
  // that loads a proposal refuses one that breaks these.
  if (p->reviewer == p->requester)
    errx(1, "%s: reviewed by its requester %s", id, p->requester->name);
  if (p->signer && !p->reviewer)
    errx(1, "%s: signed before any review", id);
  if (p->signer && (p->signer == p->requester || p->signer == p->reviewer))
    errx(1, "%s: signed by %s, who requested or reviewed it", id,
         p->signer->name);
}

// ---------------------------------------------------------------- review

static FILE *temp_with(const void *data, size_t n) {
  FILE *t = tmpfile();
  if (!t || (n && fwrite(data, 1, n, t) != n) || fflush(t) == EOF)
    err(1, "tmpfile");
  return t;
}

// The base side of a file, copied out through the no-symlink resolver
// (S_ISREG only: a fifo would block diff, a link could point anywhere).
static FILE *base_copy(int root, const char *path) {
  struct stat st;
  int fd = open_beneath(root, path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0)
    return nullptr;
  if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return nullptr;
  }
  FILE *t = tmpfile();
  char buf[1 << 16];
  ssize_t n;
  if (!t)
    err(1, "tmpfile");
  while ((n = read(fd, buf, sizeof buf)) > 0)
    if (fwrite(buf, 1, (size_t)n, t) != (size_t)n)
      err(1, "write tmpfile");
  close(fd);
  if (n < 0 || fflush(t) == EOF)
    err(1, "copy %s", path);
  return t;
}

static bool has_nul(FILE *f) {
  char buf[1 << 16];
  size_t n;
  bool nul = false;
  rewind(f);
  while (!nul && (n = fread(buf, 1, sizeof buf, f)) > 0)
    nul = memchr(buf, '\0', n) != nullptr;
  if (ferror(f))
    err(1, "read tmpfile");
  rewind(f);
  return nul;
}

static void show_content(int root, const struct change *c) {
  char a[64], b[64], sha[SHA256_HEX + 1];

  if (memchr(c->data, '\0', c->len)) {
    sha256_buf(c->data, c->len, sha);
    printf("    binary, %zu bytes, sha256 %s\n", c->len, sha);
    return;
  }
  FILE *base = base_copy(root, c->path);
  // A binary base makes diff print only "Binary files differ", which
  // would hide the new text. Show it in full instead, as an addition.
  if (base && has_nul(base)) {
    printf("    replaces a binary file; the new content in full:\n");
    fclose(base);
    base = nullptr;
  }
  FILE *next = temp_with(c->data, c->len);
  FILE *out = tmpfile();
  if (!out)
    err(1, "tmpfile");
  // diff gets the temp files as /proc/<escrow>/fd/N (same uid, so it may
  // open them); the files themselves are anonymous.
  snprintf(a, sizeof a, "/proc/%d/fd/%d", getpid(), base ? fileno(base) : -1);
  snprintf(b, sizeof b, "/proc/%d/fd/%d", getpid(), fileno(next));
  char *argv[] = {
      "diff", "-u",   "--label", "a", "--label", "b", base ? a : "/dev/null",
      b,      nullptr};
  int st = run_cmd(argv, -1, fileno(out));
  if (st > 1)
    errx(1, "diff failed");
  rewind(out);
  print_escaped(out, "");
  fclose(out);
  fclose(next);
  if (base)
    fclose(base);
}

// Everything below dir root/path, which the change will delete: the signer
// must see a recursive delete in full, not as one line. Listed from the
// workspace through the no-symlink resolver, in walk order.
static void show_deleted_tree(int root, const char *path, size_t *shown) {
  enum { DELETED_MAX = 200 };
  struct dirent **ents;

  int fd = open_beneath(root, path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (fd < 0)
    return;
  int n = scandirat(fd, ".", &ents, tree_skip_dots, tree_by_name);
  close(fd);
  if (n < 0) {
    printf("    (can't list what is below: %s)\n", strerror(errno));
    return;
  }
  for (int i = 0; i < n; i++) {
    char sub[PATH_MAX];
    snprintf(sub, sizeof sub, "%s%s%s", path, *path ? "/" : "",
             ents[i]->d_name);
    if ((*shown)++ < DELETED_MAX) {
      char *q = record_quoted(sub);
      printf("    deletes %s\n", q);
      free(q);
    }
    struct stat st;
    int sfd = open_beneath(root, sub, O_PATH | O_NOFOLLOW);
    if (sfd >= 0 && fstat(sfd, &st) == 0 && S_ISDIR(st.st_mode))
      show_deleted_tree(root, sub, shown);
    if (sfd >= 0)
      close(sfd);
    free(ents[i]);
  }
  free(ents);
}

static void show_deletions(int root, const char *path) {
  size_t shown = 0;
  show_deleted_tree(root, path, &shown);
  if (shown > 200)
    printf("    ... %zu entries deleted in all\n", shown);
}

static void show_xattrs(const struct change *c) {
  char sha[SHA256_HEX + 1], *q;
  for (size_t i = 0; i < c->nx; i++) {
    q = record_quoted(c->x[i].name);
    sha256_buf(c->x[i].value, c->x[i].len, sha);
    printf("    xattr %s, %zu bytes, sha256 %s\n", q, c->x[i].len, sha);
    free(q);
  }
}

// user.* xattrs on the live entry that the change doesn't list: apply
// removes them (apply.c: set_xattrs), so review must say so.
static void show_removed_xattrs(int root, const struct change *c) {
  static char names[XATTR_LIST_MAX];

  int fd = open_beneath(root, c->path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) {
    if (errno != ENOENT && errno != ELOOP) // ELOOP: a symlink, no xattrs
      printf("    current xattrs unreadable: %s\n", strerror(errno));
    return;
  }
  ssize_t n = flistxattr(fd, names, sizeof names);
  if (n < 0)
    printf("    current xattrs unreadable: %s\n", strerror(errno));
  for (char *p = names; n > 0 && p < names + n; p += strlen(p) + 1) {
    if (strncmp(p, "user.", 5) != 0)
      continue;
    bool kept = false;
    for (size_t i = 0; i < c->nx && !kept; i++)
      kept = strcmp(c->x[i].name, p) == 0;
    if (!kept) {
      char *q = record_quoted(p);
      printf("    xattr %s removed\n", q);
      free(q);
    }
  }
  close(fd);
}

// What the signer approves, rendered from the change set (never from
// upper/ or any stored text) against the workspace as it is now.
static void render(const struct proposal *p, bool closures) {
  char now[SHA256_HEX + 1];

  printf("proposal %s\n  requester %s\n  time      %s\n  cmd       %s\n"
         "  exit      %d\n  net       %s\n  env       %s\n  workspace %s\n  "
         "role-env  %s\n  base      %s\n"
         "  changes   %s\n",
         p->rec.id, p->requester->name, p->rec.time, p->rec.cmd, p->rec.exit,
         p->rec.net ? "yes (TCP 443, UDP 53)" : "no", p->rec.env,
         p->rec.workspace, p->rec.role_env, p->rec.base, p->rec.changes);
  if (p->reviewer)
    printf("  reviewer  %s\n", p->reviewer->name);
  if (p->signer)
    printf("  signer    %s\n", p->signer->name);
  bool moved =
      !tree_hash(p->rec.workspace, now) || strcmp(now, p->rec.base) != 0;
  if (moved)
    printf("  WARNING: the workspace no longer matches base; apply will "
           "refuse\n");
  printf("\n");

  int root = open(p->rec.workspace, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (root < 0)
    err(1, "open %s", p->rec.workspace);
  for (size_t i = 0; i < p->cs.n; i++) {
    const struct change *c = &p->cs.v[i];
    char *q = record_quoted(*c->path ? c->path : ".");
    struct stat st;
    int fd = open_beneath(root, c->path, O_PATH | O_NOFOLLOW);
    bool exists = fd >= 0 && fstat(fd, &st) == 0;
    if (fd >= 0)
      close(fd);
    if (c->op == 'D') {
      printf("D %s%s\n", q, exists && S_ISDIR(st.st_mode) ? " (dir)" : "");
      if (exists && S_ISDIR(st.st_mode))
        show_deletions(root, c->path);
    } else {
      const char *kind = c->op == 'd' || c->op == 'r' ? "dir"
                         : c->op == 'f'               ? "file"
                         : c->op == 'l'               ? "symlink"
                                                      : "fifo";
      if (exists && S_ISDIR(st.st_mode) && c->op != 'd' && c->op != 'r')
        printf("M %s dir -> %s mode %04o -> %04o", q, kind, st.st_mode & 07777,
               c->mode);
      else if (exists)
        printf("M %s %s mode %04o -> %04o", q, kind, st.st_mode & 07777,
               c->mode);
      else
        printf("A %s %s mode %04o", q, kind, c->mode);
      if (c->op == 'l') {
        char *t = record_quoted(c->data);
        printf(" -> %s", t);
        free(t);
      }
      putchar('\n');
      show_xattrs(c);
      if (exists)
        show_removed_xattrs(root, c);
      if (exists && S_ISDIR(st.st_mode) && c->op != 'd' && c->op != 'r')
        show_deletions(root, c->path);
      if (c->op == 'f')
        show_content(root, c);
    }
    free(q);
  }
  close(root);
  // Opt-in: it evaluates and builds agent-written Nix on this host
  // (closure.h), and a workspace that moved would diff the wrong base.
  if (closures && moved)
    printf("\nclosure diff: skipped, the workspace no longer matches base\n");
  else if (closures)
    closure_diff(p->rec.workspace, &p->cs);
  fflush(stdout);
}

// ------------------------------------------------------------- commands

struct args {
  const char *state, *roles, *key, *id;
  bool closures; // review/sign: also build the NixOS closure diff
};

static void parse(int argc, char *argv[], struct args *o, bool want_id) {
  static const struct option lo[] = {
      {"state", required_argument, nullptr, 's'},
      {"roles", required_argument, nullptr, 'R'},
      {"key", required_argument, nullptr, 'k'},
      {"closures", no_argument, nullptr, 'c'},
      {},
  };
  int c;
  *o = (struct args){};
  optind = 1;
  while ((c = getopt_long(argc, argv, "", lo, nullptr)) != -1) {
    switch (c) {
    case 's':
      o->state = optarg;
      break;
    case 'R':
      o->roles = optarg;
      break;
    case 'k':
      o->key = optarg;
      break;
    case 'c':
      o->closures = true;
      break;
    default:
      exit(2);
    }
  }
  if (want_id) {
    if (optind != argc - 1)
      errx(2,
           "usage: escrow %s <id> [--state DIR] [--roles FILE] "
           "[--key KEY]",
           argv[0]);
    o->id = argv[optind];
  } else if (optind != argc) {
    errx(2, "usage: escrow %s [--state DIR] [--roles FILE]", argv[0]);
  }
  o->state = state_dir(o->state);
}

static struct log_line step_line(const char *event, const struct proposal *p,
                                 const struct principal *who, const char *sig,
                                 const struct roles *roles) {
  struct log_line line = {};
  snprintf(line.event, sizeof line.event, "%s", event);
  snprintf(line.id, sizeof line.id, "%s", p->rec.id);
  snprintf(line.principal, sizeof line.principal, "%s", who->name);
  strcpy(line.record, p->record_sha);
  sha256_file(sig, line.sig);
  strcpy(line.extra, "-");
  strcpy(line.roles, roles->sha);
  return line;
}

int cmd_review(int argc, char *argv[]) {
  struct args o;
  static struct roles roles; // static: reachable at exit, for LeakSanitizer
  static struct log log;     // static: reachable at exit, for LeakSanitizer
  static struct proposal p;  // static: reachable at exit, for LeakSanitizer
  char sig[PATH_MAX];

  parse(argc, argv, &o, true);
  roles_load(&roles, roles_path(o.roles));
  log_open(&log, o.state, true);
  load(&p, &log, &roles, o.state, o.id);
  render(&p, o.closures);
  if (!o.key)
    return 0;
  if (p.reviewer)
    errx(1, "%s was already reviewed by %s", o.id, p.reviewer->name);
  sig_path(sig, p.dir, log_next_seq(&log), EV_REVIEW);
  const struct principal *who =
      sig_create(&roles, o.key, NS_REVIEW, p.record_path, sig);
  const char *why = !(who->roles & ROLE_REVIEWER) ? "is not a reviewer"
                    : who == p.requester ? "requested it: no self-review"
                                         : nullptr;
  if (why) {
    unlink(sig);
    errx(1, "%s %s", who->name, why);
  }
  struct log_line line = step_line(EV_REVIEW, &p, who, sig, &roles);
  log_append(&log, &line);
  warnx("reviewed %s as %s", o.id, who->name);
  return 0;
}

int cmd_sign(int argc, char *argv[]) {
  struct args o;
  static struct roles roles; // static: reachable at exit, for LeakSanitizer
  static struct log log;     // static: reachable at exit, for LeakSanitizer
  static struct proposal p;  // static: reachable at exit, for LeakSanitizer
  char sig[PATH_MAX];

  parse(argc, argv, &o, true);
  if (!o.key)
    errx(2, "sign needs --key");
  roles_load(&roles, roles_path(o.roles));
  log_open(&log, o.state, true);
  load(&p, &log, &roles, o.state, o.id);
  if (!p.reviewer)
    errx(1, "%s has not been reviewed", o.id);
  if (p.signer)
    errx(1, "%s was already signed by %s", o.id, p.signer->name);
  render(&p, o.closures);
  sig_path(sig, p.dir, log_next_seq(&log), EV_SIGN);
  const struct principal *who =
      sig_create(&roles, o.key, NS_SIGN, p.record_path, sig);
  const char *why = !(who->roles & ROLE_SIGNER) ? "is not a signer"
                    : who == p.requester        ? "requested it"
                    : who == p.reviewer         ? "reviewed it"
                                                : nullptr;
  if (why) {
    unlink(sig);
    errx(1, "%s %s: separation of duties", who->name, why);
  }
  struct log_line line = step_line(EV_SIGN, &p, who, sig, &roles);
  log_append(&log, &line);
  warnx("signed %s as %s", o.id, who->name);
  return 0;
}

// The apply statement, the one thing apply signs (under NS_APPLY): which
// record, the tree it produced, and the log line it follows (so replaying
// it after a truncated log needs a new signature). Kept at <run>/<seq>-apply.
static void statement(char out[512], const char *id, const char *record,
                      const char *post, const char *prev) {
  snprintf(out, 512, "escrow-apply 1\nid %s\nrecord %s\npost %s\nprev %s\n", id,
           record, post, prev);
}

static void statement_path(char out[PATH_MAX], const char *dir,
                           unsigned long seq) {
  int n = snprintf(out, PATH_MAX, "%s/%lu-apply", dir, seq);
  if (n < 0 || n >= PATH_MAX)
    errx(1, "path too long: %s/%lu-apply", dir, seq);
}

static void write_statement(const char *path, const char *text) {
  int fd =
      open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0)
    err(1, "open %s", path);
  if (write_all(fd, text, strlen(text)) < 0 || fsync(fd) < 0 || close(fd) < 0)
    err(1, "write %s", path);
}

// What a failed apply leaves behind until the swap: the stage dir, the
// statement and its signature. Any of them would block every retry.
static struct undo {
  char stage[PATH_MAX], stmt[PATH_MAX], sig[PATH_MAX];
} undo;

static void undo_apply(void) {
  struct stat st;
  if (*undo.sig)
    unlink(undo.sig);
  if (*undo.stmt)
    unlink(undo.stmt);
  if (*undo.stage && lstat(undo.stage, &st) == 0)
    remove_dir(undo.stage);
}

int cmd_apply(int argc, char *argv[]) {
  struct args o;
  static struct roles roles; // static: reachable at exit, for LeakSanitizer
  static struct log log;     // static: reachable at exit, for LeakSanitizer
  static struct proposal p;  // static: reachable at exit, for LeakSanitizer
  char now[SHA256_HEX + 1], post[SHA256_HEX + 1];
  char stage[PATH_MAX], stmt[PATH_MAX], sig[PATH_MAX];

  parse(argc, argv, &o, true);
  if (!o.key)
    errx(2, "apply needs --key (a signer's)");
  roles_load(&roles, roles_path(o.roles));
  log_open(&log, o.state, true);
  load(&p, &log, &roles, o.state, o.id);
  if (!p.signer)
    errx(1, "%s has not been signed", o.id);
  if (log_find(&log, o.id, EV_APPLY))
    errx(1, "%s was already applied", o.id);
  const char *ws = p.rec.workspace;
  if (!tree_hash(ws, now) || strcmp(now, p.rec.base) != 0)
    errx(1, "%s: the workspace moved since the proposal (base mismatch)", ws);

  // Stage: a full copy next to the workspace (same fs, so the exchange is
  // one rename), the change set applied to the copy, then swapped in.
  // Needs write access to the workspace's parent dir.
  const char *slash = strrchr(ws, '/'); // ws is absolute, no trailing /
  int n = snprintf(stage, sizeof stage, "%.*s/.%s.escrow-%s", (int)(slash - ws),
                   ws, slash + 1, o.id);
  if (n < 0 || n >= (int)sizeof stage)
    errx(1, "path too long: %s", ws);
  // cp into an existing dir would merge a crashed apply's leftovers in.
  struct stat st;
  if (lstat(stage, &st) == 0)
    errx(1, "%s exists (left by a failed apply?); remove it first", stage);
  // From here until the swap, every exit (any errx, a failed or refused
  // signature included) goes through undo_apply.
  strcpy(undo.stage, stage);
  if (atexit(undo_apply) != 0)
    errx(1, "atexit");
  char *cp[] = {"cp",       "-a",  "--no-target-directory",
                (char *)ws, stage, nullptr};
  if (run_cmd(cp, -1, -1) != 0)
    errx(1, "copy %s to %s failed", ws, stage);
  // The copy must be the reviewed base: a writer that changed the workspace
  // during the copy and changed it back would slip past the checks on ws.
  if (!tree_hash(stage, now) || strcmp(now, p.rec.base) != 0)
    errx(1, "%s: changed while being copied; nothing applied", ws);
  umask(0); // belt and braces: apply.c sets every mode explicitly anyway
  if (apply_changes(&p.cs, stage) < 0 || !tree_hash(stage, post))
    errx(1, "apply failed; the workspace is untouched");

  unsigned long seq = log_next_seq(&log);
  char text[512];
  statement_path(stmt, p.dir, seq);
  statement(text, p.rec.id, p.record_sha, post, log_hash_at(&log, log.n));
  write_statement(stmt, text);
  strcpy(undo.stmt, stmt);
  sig_path(sig, p.dir, seq, EV_APPLY);
  const struct principal *who = sig_create(&roles, o.key, NS_APPLY, stmt, sig);
  strcpy(undo.sig, sig);
  if (!(who->roles & ROLE_SIGNER) || who == p.requester)
    errx(1, "%s may not apply: needs a signer who didn't request it",
         who->name);
  // After signing: it can wait on a passphrase or a key touch, and a write
  // to the workspace during that wait must refuse the apply, not vanish
  // with the old tree. The stage is re-checked against the signed post.
  if (!tree_hash(ws, now) || strcmp(now, p.rec.base) != 0)
    errx(1, "%s: the workspace moved during apply; nothing changed", ws);
  if (!tree_hash(stage, now) || strcmp(now, post) != 0)
    errx(1, "%s: changed after apply; nothing changed", stage);
  if (renameat2(AT_FDCWD, stage, AT_FDCWD, ws, RENAME_EXCHANGE) < 0)
    err(1, "renameat2 RENAME_EXCHANGE %s", ws);
  undo = (struct undo){}; // swapped: the apply happened
  // Swap, then log. A crash in between leaves the workspace applied with no
  // apply line: verify-log still passes (the log never claims it), apply
  // refuses a retry (base moved), and <run>/<seq>-apply + .sig show it.
  struct log_line line = step_line(EV_APPLY, &p, who, sig, &roles);
  strcpy(line.extra, post);
  log_append(&log, &line);
  // stage is the old tree now. A write that landed between the last check
  // and the swap is in it: keep it rather than delete someone's work.
  if (!tree_hash(stage, now) || strcmp(now, p.rec.base) != 0)
    warnx("%s: the workspace changed just before the swap; the old tree, "
          "with that change, is kept at %s",
          ws, stage);
  else
    remove_dir(stage);
  warnx("applied %s as %s", o.id, who->name);
  return 0;
}

int cmd_verify_log(int argc, char *argv[]) {
  struct args o;
  static struct roles roles; // static: reachable at exit, for LeakSanitizer
  static struct log log;     // static: reachable at exit, for LeakSanitizer
  static struct proposal p;  // static: reachable at exit, for LeakSanitizer

  parse(argc, argv, &o, false);
  roles_load(&roles, roles_path(o.roles));
  log_open(&log, o.state, false);
  for (size_t i = 0; i < log.n; i++) {
    const struct log_line *l = &log.v[i];
    if (l->seq != i + 1)
      errx(1, "log line %zu: seq %lu out of order", i + 1, l->seq);
    if (strcmp(l->prev, log_hash_at(&log, i)) != 0)
      errx(1,
           "log line %zu: chain broken (an earlier line was changed, "
           "removed or reordered)",
           i + 1);
    // Each step happens once per id. load() below, on the log as it was at
    // this line, then checks the steps before it.
    for (size_t j = 0; j < i; j++)
      if (!strcmp(log.v[j].id, l->id) && !strcmp(log.v[j].event, l->event))
        errx(1, "log line %zu: second %s for %s", i + 1, l->event, l->id);
    struct log prefix = log;
    prefix.n = i + 1;
    load(&p, &prefix, &roles, o.state, l->id);
    if (strcmp(l->record, p.record_sha) != 0)
      errx(1, "log line %zu: record hash mismatch", i + 1);
    if (strcmp(l->event, EV_APPLY) != 0 && strcmp(l->extra, "-") != 0)
      errx(1, "log line %zu: unexpected extra", i + 1);
    if (strcmp(l->event, EV_PROPOSE) == 0) {
      // load() above verified the propose signature and the change set.
    } else if (strcmp(l->event, EV_REVIEW) == 0) {
      if (p.reviewer == p.requester)
        errx(1, "log line %zu: self-review", i + 1);
    } else if (strcmp(l->event, EV_SIGN) == 0) {
      if (!p.reviewer)
        errx(1, "log line %zu: signed before review", i + 1);
      if (p.signer == p.requester || p.signer == p.reviewer)
        errx(1, "log line %zu: separation of duties violated", i + 1);
    } else if (strcmp(l->event, EV_APPLY) == 0) {
      char stmt[PATH_MAX], want[512], got[512] = "";
      if (!p.signer)
        errx(1, "log line %zu: applied before signing", i + 1);
      statement_path(stmt, p.dir, l->seq);
      statement(want, l->id, l->record, l->extra, l->prev);
      FILE *f = fopen(stmt, "re");
      if (!f)
        err(1, "open %s", stmt);
      size_t got_n = fread(got, 1, sizeof got - 1, f);
      fclose(f);
      got[got_n] = '\0';
      if (strcmp(got, want) != 0)
        errx(1, "log line %zu: apply statement doesn't match the log", i + 1);
      const struct principal *who =
          check_step(&roles, p.dir, l, NS_APPLY, stmt, ROLE_SIGNER);
      if (who == p.requester)
        errx(1, "log line %zu: applied by the requester", i + 1);
    } else {
      errx(1, "log line %zu: unknown event %s", i + 1, l->event);
    }
  }
  printf("ok: %zu events, head %s\n", log.n, log_hash_at(&log, log.n));
  return 0;
}

int cmd_list(int argc, char *argv[]) {
  struct args o;
  static struct log log; // static: reachable at exit, for LeakSanitizer

  parse(argc, argv, &o, false);
  log_open(&log, o.state, false);
  for (size_t i = 0; i < log.n; i++) {
    const struct log_line *l = &log.v[i];
    if (strcmp(l->event, EV_PROPOSE) != 0)
      continue;
    const char *state = log_find(&log, l->id, EV_APPLY)    ? "applied"
                        : log_find(&log, l->id, EV_SIGN)   ? "signed"
                        : log_find(&log, l->id, EV_REVIEW) ? "reviewed"
                                                           : "proposed";
    char path[PATH_MAX];
    struct record r;
    join(path, "%s/runs/%s/record", o.state, l->id);
    record_read(path, &r);
    printf("%s  %s  %-9s %-12s %s\n", l->id, l->time, state, l->principal,
           r.cmd);
    record_free(&r);
  }
  return 0;
}
