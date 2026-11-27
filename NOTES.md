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
- **Witnessed log heads (later, M5 "where this goes").** Independent
  witnesses cosign `(seq, head)` so truncation or a rewrite shows up offline.
  The log is a linear chain, not a Merkle tree: a witness keeps the whole log
  to check that the new head extends the old one.
- **Inverse change set on apply (later).** Before removing the old tree,
  write the change set that undoes the apply. Revert is a normal proposal
  (review, sign, base check), never an automatic or unsigned rollback.
- **Warrant before the run (later, M5 "where this goes").** A signer
  pre-signs a scope (paths, later closure deltas) and the proposal is checked
  against it. It can only reject, never replace review or signatures. Same
  NixOS path weakness as path-scoped signer roles.
- **Roles from an SSH CA (later, M5 "where this goes").** Short-lived role
  certs and a KRL replace the static roles file and fix rotation. Offline
  audit verifies certs at the logged sign time (`-O verify-time`) and needs
  the archived CA + KRL. sk-* key types are already allowed.
- **Machine witness (later).** A CI key builds/tests the materialized
  proposal inside the jail and adds a signature. It never counts toward
  human SoD and is never the final signer.
- **in-toto export (later, low).** Statement with subject = changes sha256,
  materials = store paths. SSHSIG isn't DSSE, so stock verifiers need a
  second signer (a dependency).
- **Independent shell verifier (soon).** A ~50-line script in tests/ that
  checks a log with only `ssh-keygen -Y verify` and `sha256sum`, following
  docs/FORMATS.md. It proves the "verifiable offline without escrow" claim;
  nothing in tests/ does that today.
- **Browser signing for the web UI (later).** Removes server-held persona
  keys. OpenSSH's WebAuthn signature type is ECDSA-only
  (`webauthn-sk-ecdsa-sha2-nistp256@openssh.com`), the browser can't use the
  `ssh:` rpId, and it's unconfirmed whether `ssh-keygen -Y verify` accepts
  that signature type. Prototype that check first.
- **Bind web users to personas (later).** One login, one persona, so the
  web UI shows SoD the way the CLI enforces it instead of letting any login
  act as anyone.
- **Sign what the reviewer saw of the closure diff (later).** `--closures`
  output is advisory and unsigned; a review signature over its hash is the
  honest version.
