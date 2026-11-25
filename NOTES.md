# Notes

## ideas

- **Pin the base tree (M3).** Hash the workspace (type, mode, symlink
  targets, contents) before the run. Re-check it after the agent exits and
  before the diff, and again at `apply`, which refuses if the base moved.
  Without this, a signature approves a diff against whatever the workspace
  happens to be later. Overlay is also undefined if lower changes while
  mounted.
- **Log as a git repo (M3, needs dependency approval).** One SSH-signed
  commit per proposal (`gpg.format=ssh` already calls `ssh-keygen -Y sign`),
  with parent hashes as the chain. Use `--object-format=sha256`. The commit
  tree must hold the record (diff sha256 + base hash). `verify-log` still
  enforces requester != signer and signer roles on every commit.
- **Path-scoped signer roles (later).** CODEOWNERS for a system. Weak on
  NixOS, since any module can set anything. Matching must cover recursive
  deletions and dir-to-symlink swaps.
- **Flight-recorder trace (later, M5 "where this goes").** The exec tree
  and the files read, as blast-radius evidence. Unprivileged fanotify is
  limited to inode marks, eBPF needs privilege, and ptrace is slow.
- **OCI layer export (later, low).** upper to tar, with `.wh.` /
  `.wh..wh..opq` whiteouts. Needs a tar writer, and the target users gain
  little.
