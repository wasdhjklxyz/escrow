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
- **Effect claim alongside the diff (later, M5 "where this goes").** For
  NixOS workspaces, record the `nix eval` option-tree delta next to the file
  diff and sign both. Never instead of the diff: the option tree misses
  activation scripts, readFile'd files, and non-NixOS workspaces.
- **Transcript hash (later, needs the proxy).** Record a sha256 of the
  agent's API transcript in the proposal, not a replayable capture: LLMs are
  not deterministic, and the raw traffic carries API keys and client data.
- **Escrowed outbox (later, M5 "where this goes").** Hold outbound side
  effects (HTTP POST, kubectl apply) as pending and replay them only after
  signing. Limit: the agent sees fake responses, so read-after-write and
  non-idempotent calls can't be deferred.
- **Canaries (later, low; merge with the flight recorder).** Fake creds and
  honey hosts in the jail's view taint the proposal when touched. The jail
  holds no real secrets, so this is a reviewer signal, and detecting reads
  has the same unprivileged-tracing problem.
- **Blast-radius signer count (M3 format, policy later).** Let the record
  hold N signatures now. Later, a host-side score from the built closure
  diff (setuid, services, firewall, caps) can only raise the signer count
  above the policy minimum, never lower it.
