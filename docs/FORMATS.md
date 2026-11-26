# escrow on-disk formats

What an auditor needs to check a state dir without trusting the escrow
binary: `sha256sum` and OpenSSH `ssh-keygen -Y` (OpenSSH ≥ 8.9) check the
chain, the signatures and the record/change-set hashes. Checking a tree
against `base` or `post` also needs the tree-hash serializer below.
Version 1 of every format.

## State dir

```
<state>/log                     hash-chained event log
<state>/runs/<id>/record        the proposal record (what everyone signs)
<state>/runs/<id>/changes       the frozen change set (what apply writes)
<state>/runs/<id>/<seq>-<event>.sig   SSHSIG for log line <seq>
<state>/runs/<id>/<seq>-apply   the apply statement (signed by <seq>-apply.sig)
<state>/runs/<id>/upper/ work/ root/ log    run scratch: the agent's overlay,
                                its output log; not needed for audit
```

`<id>` is six characters of `[A-Za-z0-9]` (mkdtemp's alphabet). Keep
`record`, `changes`, the signatures and statements for audit; `upper/` and
`work/` can be deleted once a proposal is applied or abandoned.

## Roles file

One principal per line; `#` comments and blank lines are ignored:

```
<principal> <role>[,<role>...] <keytype> <base64> [comment]
```

- principal: `[a-z0-9._-]{1,64}`, unique. (OpenSSH treats the
  allowed_signers principal field as a pattern list, so `*` or `a,b`
  would match others.)
- roles: `requester`, `reviewer`, `signer`.
- keytype: `ssh-ed25519`, `sk-ssh-ed25519@openssh.com`,
  `ecdsa-sha2-nistp{256,384,521}`, `sk-ecdsa-sha2-nistp256@openssh.com`,
  `ssh-rsa`. Certificates and `cert-authority` lines are not accepted.
- each key appears once, so distinct principals are distinct keys.

The equivalent allowed_signers file is `<principal> <keytype> <base64>` per
line. Every record and log line pins the sha256 of the roles file it was
made under; verifying needs that same file (keep old versions). `escrow
verify-log` takes one roles file, so a log spanning a roles change needs
an independent verifier today.

## Record (`record`)

Text, `key value` per line, keys in exactly this order, every byte
printable ASCII (0x20–0x7e), `\n` line ends:

```
escrow-record 1
id <id>
time <YYYY-MM-DDTHH:MM:SSZ>
workspace <absolute path, needs no quoting, no trailing />
cmd <argv: each element quoted (below), joined by one space>
exit <0..255; 128+N = killed by signal N>
net <0 or 1: whether the agent had --net>
env <the --env variable names, space-separated, or ->   (never values)
escrow <path of the escrow binary, quoted>
role-policy <sha256 of the role policy file>
role-env <role env store path>
store <store path>              (zero or more)
roles <sha256 of the roles file>
base <tree hash of the workspace before the run>
changes <sha256 of changes>
```

Quoting: a value with no byte ≤ 0x20, ≥ 0x7f, `"` or `\` (and not empty)
is written as is. Otherwise it is wrapped in `"`, with `"` and `\` written
as `\"` and `\\`, other unsafe bytes as `\ooo` (three octal digits), and
spaces kept. Empty is `""`.

`escrow`, `role-policy`, `role-env` and `store` are attested by the
requester (she runs escrow), not observed by a third party.

## Change set (`changes`)

```
"escrow-changes 1\n"
entry*
entry  = "<op> <mode> <pathlen> <datalen>\n" path data xattr* "e\n"
xattr  = "x <namelen> <vallen>\n" name value
```

- op: `r` workspace root (path empty), `d` dir, `f` file (data = bytes),
  `l` symlink (data = target, mode 777), `p` fifo, `D` delete recursively
  (mode 0).
- mode: octal, no leading zeros, ≤ 07777, never setuid/setgid; sticky only
  on `d`/`r`. Lengths decimal, no leading zeros. Single spaces. Header
  line ≤ 80 bytes.
- path: relative; components non-empty, ≤ 255 bytes, not `.` or `..`; no
  leading, trailing or doubled `/`; < 4096 bytes.
- Entries strictly increasing in walk order: compare paths component by
  component with strcmp (bytewise); an ancestor sorts before its
  descendants. So no path appears twice; `r` can only be first.
- xattrs: only on `r`/`d`/`f`; names `user.*` but not `user.overlay.*`,
  ≤ 255 bytes, each name once; values ≤ 64 KiB. An entry's `x` lines are
  its complete `user.*` set: apply removes any others.
- `f`/`l`/`p` replace whatever is at the path. `d` makes a dir (replacing
  a non-dir) or keeps an existing one with its contents, then sets its
  mode and xattrs after all entries. `D` entries under a path already
  deleted or replaced are omitted.

## Tree hash (`base`, apply's `post`)

sha256 of this byte stream. `F(s)` = s followed by NUL; `L(b)` =
F(decimal length of b) followed by the bytes b; `X` = for each `user.*`
xattr in strcmp order of names: F("x") F(name) L(value).

```
F("escrow-tree 1") F(root mode) X(root) W(root)
W(dir) = for each entry, names in strcmp order:  E(entry);  then F("end")
E      = F(type) F(mode) F(path) payload
         type f: L(file bytes) X     type d: X W(dir)
         type l: L(target)           type p/s/c/b: F(decimal st_rdev)
```

mode is `st_mode & 07777` in octal, no leading zeros (setuid, setgid and
sticky included). path is relative to the tree root, `a/b` (no trailing
`/`). Owners and timestamps are not hashed. Symlinks are never followed.

## Log (`log`)

One line per event, fields separated by one space, every byte printable
ASCII (0x20–0x7e), ≤ 1023 bytes:

```
<seq> <time> <event> <id> <principal> <record-sha> <sig-sha> <extra> <roles-sha> <prev>
```

- seq: 1, 2, 3, ... (decimal, no leading zeros). time as in the record.
- event: `propose`, `review`, `sign`, `apply`.
- sig-sha: sha256 of `<run>/<seq>-<event>.sig`.
- extra: `-`, except for `apply`: the tree hash after apply.
- prev: sha256 of the previous line including its `\n`; 64 zeros on line 1.

## Signatures

`ssh-keygen -Y sign -n <namespace>` (SSHSIG), verified with
`ssh-keygen -Y verify -f allowed_signers -I <principal> -n <namespace>
-s <sig> < <data>`.

| event   | namespace        | signed data          | signer must          |
|---------|------------------|----------------------|----------------------|
| propose | `escrow-propose` | `record`             | be a requester       |
| review  | `escrow-review`  | `record`             | be a reviewer, ≠ requester |
| sign    | `escrow-sign`    | `record`             | be a signer, ≠ requester, ≠ reviewer |
| apply   | `escrow-apply`   | `<seq>-apply`        | be a signer, ≠ requester |

The apply statement is exactly:

```
escrow-apply 1
id <id>
record <record-sha>
post <tree hash after apply>
prev <prev of the apply log line>
```

## What verify-log checks, and what it can't

For every line: seq and prev chain; each step once per id and in order
(propose < review < sign < apply); the line's and the record's roles hash
equal the roles file given; record and change-set hashes; the signature
file's hash; the signature under the event's namespace; the principal's
role; requester ≠ reviewer ≠ signer; the apply statement.

The chain is unkeyed. Anyone who can write the state dir can truncate the
log, or rebuild it from their own proposals; signatures still bind what
each person signed, but a truncation is only visible against a head hash
kept elsewhere (verify-log prints it). Log-line times are not signed; the
record's `time` is signed, but it comes from the requester's clock.
