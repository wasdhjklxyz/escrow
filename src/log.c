#include "log.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

static const char zeros[] =
    "0000000000000000000000000000000000000000000000000000000000000000";

static void format(char *out, size_t n, const struct log_line *l) {
  snprintf(out, n, "%lu %s %s %s %s %s %s %s %s %s\n", l->seq, l->time,
           l->event, l->id, l->principal, l->record, l->sig, l->extra, l->roles,
           l->prev);
}

static void add(struct log *l, const struct log_line *line) {
  struct log_line *v = reallocarray(l->v, l->n + 1, sizeof *v);
  if (!v)
    err(1, "reallocarray");
  l->v = v;
  v[l->n++] = *line;
}

void log_open(struct log *l, const char *state, bool writer) {
  char path[PATH_MAX], text[1024];

  *l = (struct log){};
  int n = snprintf(path, sizeof path, "%s/log", state);
  if (n < 0 || n >= (int)sizeof path)
    errx(1, "path too long: %s/log", state);
  // Readers (list, verify-log) never create a log: an empty one would
  // verify as "ok: 0 events". They work on a read-only copy too.
  l->fd = writer
              ? open(path, O_RDWR | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC,
                     0600)
              : open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (l->fd < 0)
    err(1, "open %s", path);
  int op = writer ? LOCK_EX : LOCK_SH;
  if (flock(l->fd, op | LOCK_NB) < 0) {
    if (errno != EWOULDBLOCK)
      err(1, "flock %s", path);
    warnx("waiting for the lock on %s", path);
    if (flock(l->fd, op) < 0)
      err(1, "flock %s", path);
  }
  int dfd = dup(l->fd);
  FILE *f = dfd < 0 ? nullptr : fdopen(dfd, "r");
  if (!f)
    err(1, "open %s", path);
  if (fseek(f, 0, SEEK_SET) < 0)
    err(1, "seek %s", path);
  size_t lineno = 0;
  while (fgets(text, sizeof text, f)) {
    struct log_line line = {};
    char tail;
    lineno++;
    if (!strchr(text, '\n'))
      errx(1, "%s:%zu: line too long or unterminated", path, lineno);
    if (sscanf(text, "%lu %31s %15s %15s %71s %64s %64s %64s %64s %64s%c",
               &line.seq, line.time, line.event, line.id, line.principal,
               line.record, line.sig, line.extra, line.roles, line.prev,
               &tail) != 11 ||
        tail != '\n')
      errx(1, "%s:%zu: malformed line", path, lineno);
    // The text must be exactly what format() writes, or two lines that
    // parse the same could hash differently.
    char again[1024];
    format(again, sizeof again, &line);
    if (strcmp(again, text) != 0)
      errx(1, "%s:%zu: non-canonical line", path, lineno);
    sha256_buf(text, strlen(text), line.hash);
    add(l, &line);
  }
  if (ferror(f))
    err(1, "read %s", path);
  fclose(f);
}

unsigned long log_next_seq(const struct log *l) {
  return l->n ? l->v[l->n - 1].seq + 1 : 1;
}

void log_append(struct log *l, struct log_line *line) {
  char text[1024];
  time_t now = time(nullptr);

  line->seq = log_next_seq(l);
  strftime(line->time, sizeof line->time, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
  strcpy(line->prev, log_hash_at(l, l->n));
  format(text, sizeof text, line);
  size_t len = strlen(text);
  if (write(l->fd, text, len) != (ssize_t)len || fsync(l->fd) < 0)
    err(1, "append log");
  sha256_buf(text, len, line->hash);
  add(l, line);
}

const struct log_line *log_find(const struct log *l, const char *id,
                                const char *event) {
  for (size_t i = l->n; i-- > 0;)
    if (strcmp(l->v[i].id, id) == 0 && strcmp(l->v[i].event, event) == 0)
      return &l->v[i];
  return nullptr;
}

const char *log_hash_at(const struct log *l, size_t n) {
  return n ? l->v[n - 1].hash : zeros;
}
